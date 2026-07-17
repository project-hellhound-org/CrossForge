"""
CrossForge SSRF Agent — Native Adaptive Crawler (Recon, pre-Phase-0)
=======================================================================
WHY THIS MODULE EXISTS
------------------------
Every previous version of CrossForge hard-required a pre-built Spider JSON
file as input (see main.py: `if not args.input: err("No input file...")`).
That's an external dependency the operator has to satisfy with a *different*
tool before CrossForge can even start. This module removes that dependency:
when no --input is supplied, CrossForge does its own recon.

THIS IS NOT A SHORTCUT AROUND THE EXISTING TRIAGE LOGIC
----------------------------------------------------------
The crawler's ONLY job is discovery — finding endpoints, params, and forms.
It does not decide what's SSRF-relevant. It emits its findings in the exact
Spider-JSON shape (`{"endpoints": [...], "meta": {...},
"target_response_headers": {...}}`) that spider_adapter.detect_spider_format()
already recognises, so crawler-sourced candidates flow through the SAME
word-boundary triage, prescore.score_candidate() relevance filtering,
dedup, and HOST_HEADER gating that an externally-supplied spider file gets.
A crawled "username" query param is dropped for the exact same reason a
spider-supplied one is: prescore gives it 0.0 and spider_adapter.adapt()
filters zero-score candidates before Phase 0 ever starts. One filtering
codepath, two possible sources.

DESIGN PRINCIPLES
-------------------
  1. READ-ONLY RECON. GET requests only. Forms are PARSED for structure
     (action, method, field names) but never SUBMITTED — CrossForge never
     guesses at login credentials or triggers state changes during crawl.
  2. SAME-ORIGIN SCOPE GUARD. Stays on the target's host by default.
     --crawl-scope can add explicit extra hosts (e.g. an API subdomain);
     arbitrary external links are never followed.
  3. SESSION-SAFETY SKIP LIST. Logout/delete/deactivate-shaped paths are
     never fetched, even via GET — GET-based logout endpoints are common
     enough that blindly crawling them would kill an authenticated
     session mid-scan. See _DESTRUCTIVE_PATH_RE.
  4. ADAPTIVE BUDGET. A 12-page brochure site and a 3,000-route
     application shouldn't cost the same request budget. AdaptiveBudget
     tracks the *yield* (new in-scope links per page fetched) at each
     BFS depth and expands or halts the page ceiling based on it —
     genuinely adaptive to whatever's on the other end, not a fixed N.
  5. JS-AWARE, WITH AN OPTIONAL REAL BROWSER. Linked and inline <script>
     content is always statically pattern-matched for fetch()/axios/XHR
     call strings — no dependency needed. When the static pass clearly
     under-delivers (few endpoints found — the signature of a pure
     client-side-routed SPA whose initial HTML is an empty shell) and
     `playwright` is installed, a headless-Chromium pass renders the page
     for real and watches the network traffic and final DOM it produces.
     Escalate-on-demand, not always-on — a plain server-rendered site
     never pays the cost of spinning up a browser.
  6. robots.txt / sitemap.xml AS SEEDS, NOT FENCES. This is an authorised
     pentest tool (operator already confirmed authorisation for exploit
     mode elsewhere in the pipeline) — Disallow entries are exactly the
     paths an attacker would try first, so they're added to the crawl
     frontier rather than treated as an access restriction.

WHAT THE HEADLESS PASS DELIBERATELY DOES NOT DO
---------------------------------------------------
It does not fill in form fields with synthetic data and click Submit, and
it does not click arbitrary on-page buttons to shake more routes loose.
That's a real technique some SPA-scanning tools use, but it means the
crawler performs state-changing actions on the target — creating records,
triggering whatever an unlabelled button is wired to, submitting a
half-filled form — during what's supposed to be read-only recon. That's a
real risk on anything production-adjacent, and not a strong enough
discovery win to accept silently as a default. Rendering the page and
watching what it loads/calls on its own recovers most of the same SPA API
surface without the target ever doing anything it wasn't already going to
do on a normal page load. Interaction-driven discovery (form-fill,
click-through) is a legitimate feature for a *separately scoped, opt-in*
engagement mode — not something this module does by default.

LIMITATIONS (documented, not hidden)
--------------------------------------
  - Headless rendering is opt-in-by-availability: if `playwright` isn't
    installed (`pip install crossforge[render]` +
    `playwright install chromium`), the crawler logs one clear line and
    falls back to the static pass only — it does not error out.
  - No auth-flow traversal. If reaching the interesting surface requires
    login, supply --bearer/--cookie so the crawler's requests (both the
    static pass and the headless one) carry an already-authenticated
    session; it will not attempt to log in itself.
"""

from __future__ import annotations

import asyncio
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser

import httpx

from core.http_client import RateLimiter
from core.console import section, info, ok, warn, dim, tprint, color, C

# Phase 1 rebuild additions — each of these is a standalone module the
# crawler calls into; none of them reach back into crawler.py, so any one
# of them can be disabled/removed without touching this file beyond the
# call sites marked "Phase 1 rebuild" below.
from core import recon_quality
from core import js_intel
from core import dns_intel
from core import subdomain_enum
from core import wayback_probe

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class CrawlConfig:
    max_pages_floor:   int   = 40      # starting page budget
    max_pages_ceiling:  int  = 400     # absolute cap regardless of yield
    max_depth:          int  = 5
    concurrency:         int = 8
    request_timeout:     float = 8.0
    max_crawl_seconds:   float = 120.0  # wall-clock safety valve
    same_origin_only:    bool = True
    extra_scope_hosts:   list[str] = field(default_factory=list)
    js_static_analysis:  bool = True
    max_js_bytes:        int  = 3_000_000  # [Phase 1 rebuild bugfix] was 400_000 —
    # too small for real SPA bundles (Angular/React/Vue apps routinely ship
    # 500KB-3MB+ per bundle); see _analyze_js_url's truncate-not-drop fix.
    # This cap now bounds the regex pass, not "whether analysis happens at all".
    respect_robots_as_seed: bool = True
    user_agent: str = "CrossForge/1.0 (+authorised-security-assessment)"

    # ---- Headless rendering pass (optional, requires `pip install
    # crossforge[render]` then `playwright install chromium`) ----
    # Purely observational: loads each seed page in a real headless
    # Chromium, watches the network traffic and final DOM the page
    # produces *on its own*, and records what it sees. It does NOT fill
    # in forms, click buttons, or otherwise interact with the page — see
    # core/crawler.py's module docstring for why that's a deliberate
    # choice, not an oversight.
    headless_enabled: bool = True
    headless_force: bool = False              # render even if static crawl found plenty
    headless_skip_if_endpoints_ge: int = 15    # else: only escalate when static crawl underdelivers
    headless_max_seed_pages: int = 3           # base URL + up to N more from the static pass
    headless_timeout_ms: int = 20_000
    headless_block_resource_types: tuple = ("image", "font", "media")

    # ---- Phase 1 rebuild additions ----------------------------------
    # Quality gate (core/recon_quality.py) — on by default. Pure recall/
    # precision improvement with no scope or third-party-service
    # implications, so unlike the three flags below it doesn't need an
    # opt-in default.
    quality_gate_enabled: bool = True

    # JS variable-resolution + route-table depth (core/js_intel.py) — on
    # by default, same rationale as the quality gate: additive discovery,
    # no scope/third-party implications, folds into the existing
    # js_static_analysis pass rather than being a separate toggle.

    # security.txt as an extra seed source, alongside the existing
    # robots.txt/sitemap.xml handling — same trust model as those two,
    # on by default.
    respect_security_txt_as_seed: bool = True

    # DNS intelligence (core/dns_intel.py) — informational only, resolves
    # hosts already in scope (never expands scope on its own), on by
    # default. See that module's docstring for the optional-dependency
    # (dnspython) graceful-degrade behaviour.
    dns_intel_enabled: bool = True

    # Subdomain enumeration (core/subdomain_enum.py) — OFF by default:
    # queries a third-party CT-log aggregator (crt.sh) about the target
    # domain, and results are reported for operator review only (never
    # auto-added to crawl scope — see that module's docstring). Off by
    # default so a scan never talks to a third-party service the operator
    # didn't explicitly ask for.
    subdomain_enum_enabled: bool = False
    subdomain_enum_limit: int = 50

    # Wayback Machine historical-URL seeding (core/wayback_probe.py) — OFF
    # by default for the same third-party-dependency reason, plus historical
    # URLs can be stale enough to waste probe budget on 404s. See that
    # module's docstring.
    wayback_enabled: bool = False
    wayback_limit: int = 200

    # API wordlist probe — probes common REST/API paths not visible in HTML/JS.
    # On by default: it uses HEAD/OPTIONS so it's low-impact (no body sent,
    # no payloads injected) and adds the discovered paths to the crawl corpus
    # for prescore to evaluate. Set wordlist_probe_enabled: false to disable.
    wordlist_probe_enabled: bool = True
    wordlist_probe_limit: int = 80   # max paths to probe per scan

    @classmethod
    def from_dict(cls, d: dict, overrides: dict | None = None) -> "CrawlConfig":
        cfg = cls(
            max_pages_floor      = d.get("max_pages_floor", 40),
            max_pages_ceiling    = d.get("max_pages_ceiling", 400),
            max_depth            = d.get("max_depth", 5),
            concurrency          = d.get("concurrency", 8),
            request_timeout      = d.get("request_timeout", 8.0),
            max_crawl_seconds    = d.get("max_crawl_seconds", 120.0),
            same_origin_only     = d.get("same_origin_only", True),
            extra_scope_hosts    = list(d.get("extra_scope_hosts", []) or []),
            js_static_analysis   = d.get("js_static_analysis", True),
            max_js_bytes         = d.get("max_js_bytes", 3_000_000),
            respect_robots_as_seed = d.get("respect_robots_as_seed", True),
            user_agent           = d.get("user_agent", cls.user_agent),
            headless_enabled      = d.get("headless_enabled", True),
            headless_force        = d.get("headless_force", False),
            headless_skip_if_endpoints_ge = d.get("headless_skip_if_endpoints_ge", 15),
            headless_max_seed_pages       = d.get("headless_max_seed_pages", 3),
            headless_timeout_ms           = d.get("headless_timeout_ms", 20_000),
            headless_block_resource_types = tuple(d.get(
                "headless_block_resource_types", ("image", "font", "media")
            )),
            quality_gate_enabled          = d.get("quality_gate_enabled", True),
            respect_security_txt_as_seed  = d.get("respect_security_txt_as_seed", True),
            dns_intel_enabled              = d.get("dns_intel_enabled", True),
            subdomain_enum_enabled         = d.get("subdomain_enum_enabled", False),
            subdomain_enum_limit           = d.get("subdomain_enum_limit", 50),
            wayback_enabled                = d.get("wayback_enabled", False),
            wayback_limit                  = d.get("wayback_limit", 200),
            wordlist_probe_enabled         = d.get("wordlist_probe_enabled", True),
            wordlist_probe_limit           = d.get("wordlist_probe_limit", 80),
        )
        for k, v in (overrides or {}).items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


# ---------------------------------------------------------------------------
# Safety / scope regexes
# ---------------------------------------------------------------------------

# Never GET-fetch these even in scope — GET-based logout/destroy endpoints
# are common enough that crawling them would silently kill the operator's
# authenticated session mid-scan. [Safety-1]
_DESTRUCTIVE_PATH_RE = re.compile(
    r"/(logout|log-out|signout|sign-out|delete|remove|destroy|"
    r"unsubscribe|deactivate|revoke)(?:$|/|\?)",
    re.IGNORECASE,
)

_SKIP_EXTENSIONS = frozenset({
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "svg",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mp3", "wav", "avi", "mov",
    "zip", "tar", "gz", "rar", "7z",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
})

_JS_ENDPOINT_PATTERNS = [
    re.compile(r"""fetch\(\s*[`'"]([^`'"]+)[`'"]""", re.IGNORECASE),
    re.compile(r"""axios(?:\.\w+)?\(\s*[`'"]([^`'"]+)[`'"]""", re.IGNORECASE),
    re.compile(r"""axios\.\w+\(\s*[`'"]([^`'"]+)[`'"]""", re.IGNORECASE),
    re.compile(r"""\.open\(\s*[`'"]\w+[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]""", re.IGNORECASE),
    re.compile(r"""\$\.(?:get|post|ajax|getJSON)\(\s*(?:\{\s*url\s*:\s*)?[`'"]([^`'"]+)[`'"]""", re.IGNORECASE),
    re.compile(r"""url\s*:\s*[`'"]([^`'"]+)[`'"]""", re.IGNORECASE),
]
# Generic fallback: quoted path-shaped strings referencing API-ish routes.
_JS_PATH_FALLBACK_RE = re.compile(
    r"""[`'"](/(?:api|v[0-9]+|graphql|rest|internal|svc|service)[a-zA-Z0-9_\-/]{0,80})[`'"]""",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Lightweight HTML parser (stdlib only — no bs4 dependency)
# ---------------------------------------------------------------------------

@dataclass
class _FormInfo:
    action: str
    method: str
    fields: list[str] = field(default_factory=list)
    # Phase 1 rebuild: tracked so multipart/form-data forms (the file-upload
    # / media-processing shape — profile picture URL import, "convert this
    # document" services, etc.) can be tagged distinctly from a plain form
    # submission. See _record_endpoint_fields' bucket selection below and
    # spider_adapter.py's additive "multipart" bucket support.
    enctype: str = "application/x-www-form-urlencoded"


class _PageParser(HTMLParser):
    """
    Extracts links, forms (structure only — never submitted), script
    sources / inline script bodies, and an optional <base href> from
    one HTML document.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.links: list[str] = []
        self.script_srcs: list[str] = []
        self.inline_js: list[str] = []
        self.forms: list[_FormInfo] = []
        self._in_script = False
        self._script_buf: list[str] = []
        self._cur_form: _FormInfo | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        tag = tag.lower()
        if tag == "base" and a.get("href"):
            self.base_href = a["href"]
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            self._in_script = True
            self._script_buf = []
            if a.get("src"):
                self.script_srcs.append(a["src"])
        elif tag == "form":
            self._cur_form = _FormInfo(
                action=a.get("action", ""),
                method=(a.get("method") or "GET").upper(),
                enctype=(a.get("enctype") or "application/x-www-form-urlencoded").lower(),
            )
        elif tag in ("input", "select", "textarea") and self._cur_form is not None:
            name = a.get("name")
            if name:
                self._cur_form.fields.append(name)
        elif tag == "link" and a.get("rel") == "canonical" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "script":
            self._in_script = False
            if self._script_buf:
                self.inline_js.append("".join(self._script_buf))
        elif tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


# ---------------------------------------------------------------------------
# Adaptive budget
# ---------------------------------------------------------------------------

class AdaptiveBudget:
    """
    Tracks new-link yield per BFS depth level and adjusts the page ceiling.

    RATIONALE: a fixed page cap either wastes budget on small sites or
    stops early on large ones, both of which hurt coverage. Instead, we
    measure yield = (new in-scope URLs discovered this level) / (pages
    fetched this level). High sustained yield → the site is bigger than
    our starting assumption, raise the ceiling. Yield collapsing toward
    zero → we've hit the long tail (pagination, near-duplicate pages);
    stop deepening even if budget remains.
    """

    GROWTH_THRESHOLD = 0.5   # yield above this → expand budget
    STALL_THRESHOLD  = 0.05  # yield below this → stop expanding depth
    GROWTH_INCREMENT = 60

    def __init__(self, cfg: CrawlConfig):
        self.cfg = cfg
        self.budget = cfg.max_pages_floor
        self.pages_fetched = 0
        self.stalled = False

    def record_level(self, pages_this_level: int, new_links_this_level: int) -> None:
        if pages_this_level == 0:
            return
        yield_ratio = new_links_this_level / pages_this_level
        if yield_ratio >= self.GROWTH_THRESHOLD and self.budget < self.cfg.max_pages_ceiling:
            self.budget = min(self.cfg.max_pages_ceiling, self.budget + self.GROWTH_INCREMENT)
        elif yield_ratio < self.STALL_THRESHOLD:
            self.stalled = True

    def has_room(self) -> bool:
        return self.pages_fetched < self.budget and not self.stalled

    def consume(self, n: int = 1) -> None:
        self.pages_fetched += n


# ---------------------------------------------------------------------------
# Internal endpoint accumulator
# ---------------------------------------------------------------------------

@dataclass
class _EndpointAccumulator:
    method: str
    params_detail: dict[str, set] = field(default_factory=lambda: {
        # "multipart" is a Phase 1 rebuild addition — see _FormInfo.enctype
        # and _fetch_and_parse's bucket selection below. Kept as its own
        # bucket (not folded into "form") so spider_adapter.py can route it
        # to ParamLocation.BODY_MULTIPART instead of BODY_FORM.
        "query": set(), "form": set(), "js": set(), "multipart": set(),
    })
    observed_values: dict[str, str] = field(default_factory=dict)
    observed_status: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Native crawler
# ---------------------------------------------------------------------------

class NativeCrawler:
    """
    Same-origin, adaptive BFS crawler. Produces a Spider-format dict:
        {"endpoints": [...], "meta": {...}, "target_response_headers": {...}}
    ready to be handed to core.spider_adapter.adapt() unchanged.
    """

    def __init__(self, cfg: CrawlConfig, rate_limiter: RateLimiter | None = None,
                 proxy: str | None = None, extra_headers: dict | None = None):
        self.cfg = cfg
        self._limiter = rate_limiter or RateLimiter()
        client_kwargs = dict(
            timeout=cfg.request_timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": cfg.user_agent, **(extra_headers or {})},
        )
        if proxy:
            client_kwargs["proxy"] = proxy
        self._client = httpx.AsyncClient(**client_kwargs)

        self._visited_pages: set[str] = set()      # scheme+host+path, dedup key
        self._endpoints: dict[tuple[str, str], _EndpointAccumulator] = {}
        self._forms_found = 0
        self._js_files_analyzed = 0
        self._js_files_truncated = 0   # [Phase 1 rebuild bugfix] visibility for the truncate-not-drop fix above
        self._target_response_headers: dict = {}

        # Phase 1 rebuild additions. quality_baseline is None until
        # crawl() establishes it (see _establish_quality_baseline) — every
        # call site checks for None so a failed/skipped baseline never
        # raises, it just leaves the quality gate effectively disabled for
        # this run. recon_intel accumulates the informational-only
        # DNS/subdomain/wayback results surfaced in the final meta dict.
        self._quality_baseline: recon_quality.QualityBaseline | None = None
        self._recon_intel: dict = {
            "subdomains": None, "dns": None, "wayback": None,
        }
        # [Safety-2] Populated at the start of crawl(). Every endpoint-record
        # path (_record_endpoint_from_url / _record_endpoint_fields) checks
        # against this — NOT just the fetch/follow path — so an out-of-scope
        # URL can never become a fuzzing candidate even if it's merely
        # *linked to* from an in-scope page. A pentest tool that lets scope
        # leak into its candidate list is a real authorization problem, not
        # just noise, so this is enforced centrally rather than trusted to
        # every call site.
        self._allowed_hosts: set[str] = set()

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def crawl(self, base_url: str) -> dict:
        t_start = time.monotonic()
        base = httpx.URL(base_url)
        allowed_hosts = {base.host, *self.cfg.extra_scope_hosts}
        self._allowed_hosts = allowed_hosts

        budget = AdaptiveBudget(self.cfg)
        sem = asyncio.Semaphore(self.cfg.concurrency)

        # ---- Phase 1 rebuild: quality-gate baseline -------------------
        # Runs before anything else touches the page budget so every
        # subsequent fetch (including the seed pages below) benefits from
        # it. See core/recon_quality.py's module docstring; a failed/
        # skipped canary probe just leaves the quality gate off for this
        # run rather than raising.
        if self.cfg.quality_gate_enabled:
            self._quality_baseline = await recon_quality.establish_baseline(
                self._client, str(base), timeout=self.cfg.request_timeout,
            )

        # ---- Phase 1 rebuild: subdomain enumeration (opt-in) -----------
        # Informational only — see core/subdomain_enum.py's docstring for
        # why results are never auto-added to allowed_hosts/frontier.
        # Feeds DNS intel below (base host + any discovered subdomains).
        recon_hosts = [base.host]
        if self.cfg.subdomain_enum_enabled:
            sub_result = await subdomain_enum.enumerate_subdomains(
                base.host, client=self._client, limit=self.cfg.subdomain_enum_limit,
            )
            self._recon_intel["subdomains"] = sub_result
            if sub_result["subdomains"]:
                info(
                    f"Subdomain enum (crt.sh) — {color(str(len(sub_result['subdomains'])), C.BWHITE, C.BOLD)} "
                    f"found (informational — not auto-added to crawl scope; use --crawl-scope to include one)"
                )
                recon_hosts.extend(sub_result["subdomains"])
            elif sub_result.get("skip_reason"):
                dim(f"Subdomain enum skipped: {sub_result['skip_reason']}")

        # ---- Phase 1 rebuild: DNS intelligence -------------------------
        # Informational only, resolves hosts already in scope (base host)
        # plus any subdomain_enum results — never expands crawl scope on
        # its own. Also lays the groundwork for a real DNS-rebinding
        # detector (see core/dns_intel.py's module docstring).
        if self.cfg.dns_intel_enabled:
            self._recon_intel["dns"] = await dns_intel.resolve_hosts(recon_hosts)

        frontier: list[tuple[str, int]] = [(str(base), 0)]  # (url, depth)
        self._visited_pages.add(_page_key(str(base)))

        # ---- Seed from robots.txt / sitemap.xml / security.txt --------
        # [design principle 6] — security.txt parsing is a Phase 1 rebuild
        # addition folded directly into _collect_seeds below.
        seeds = await self._collect_seeds(base)
        for s in seeds:
            key = _page_key(s)
            if key not in self._visited_pages and _in_scope(s, allowed_hosts):
                self._visited_pages.add(key)
                frontier.append((s, 0))

        # ---- Phase 1 rebuild: Wayback Machine historical seeding (opt-in) --
        # Same-origin filter applied identically to robots/sitemap seeds
        # above — a historical URL on an out-of-scope host is dropped, not
        # auto-added to scope. See core/wayback_probe.py's docstring.
        if self.cfg.wayback_enabled:
            wb_result = await wayback_probe.fetch_historical_urls(
                base.host, client=self._client, limit=self.cfg.wayback_limit,
            )
            self._recon_intel["wayback"] = wb_result
            added = 0
            for u in wb_result["urls"]:
                key = _page_key(u)
                if key not in self._visited_pages and _in_scope(u, allowed_hosts) and not _should_skip(u):
                    self._visited_pages.add(key)
                    frontier.append((u, 0))
                    added += 1
            if added:
                info(f"Wayback Machine — +{color(str(added), C.BWHITE, C.BOLD)} historical URL(s) added to frontier")
            elif wb_result.get("skip_reason"):
                dim(f"Wayback seeding skipped: {wb_result['skip_reason']}")

        depth = 0
        while frontier and depth <= self.cfg.max_depth and budget.has_room():
            if time.monotonic() - t_start > self.cfg.max_crawl_seconds:
                dim(f"Crawl wall-clock limit ({self.cfg.max_crawl_seconds:.0f}s) reached — stopping.")
                break

            this_level = frontier[: max(0, budget.budget - budget.pages_fetched)]
            frontier = frontier[len(this_level):]
            if not this_level:
                break

            results = await asyncio.gather(*[
                self._fetch_and_parse(url, sem) for url, _d in this_level
            ], return_exceptions=True)
            budget.consume(len(this_level))

            new_links: list[str] = []
            for (url, d), res in zip(this_level, results):
                if isinstance(res, Exception) or res is None:
                    continue
                links, next_depth_urls = res
                for link in links:
                    key = _page_key(link)
                    if key in self._visited_pages:
                        continue
                    if not _in_scope(link, allowed_hosts):
                        continue
                    if _should_skip(link):
                        continue
                    self._visited_pages.add(key)
                    new_links.append(link)

            budget.record_level(len(this_level), len(new_links))
            depth += 1
            frontier.extend((u, depth) for u in new_links)

        # ---- Optional headless-render escalation [design principle 5] ----
        headless_stats = await self._run_headless_pass(str(base), allowed_hosts)

        # ---- API wordlist probe -----------------------------------------------
        # SPAs built on frameworks like Express, Spring Boot, Django REST, Rails
        # don't link their API paths in HTML — they're called by JS at runtime.
        # Even with headless rendering + network capture we only see endpoints that
        # FIRED during our brief render window. Many critical SSRF endpoints
        # (import, webhook, proxy, fetch, preview) are behind POST-only paths
        # that never fire on the landing page. This pass probes a curated list of
        # common API path patterns with a cheap OPTIONS/HEAD probe to confirm
        # existence, then records them as candidates for prescore to evaluate.
        # Bounded at config.wordlist_probe_limit to stay within time budget.
        if self.cfg.wordlist_probe_enabled:
            await self._run_wordlist_probe(str(base), allowed_hosts)

        elapsed = time.monotonic() - t_start
        endpoints = self._finalize_endpoints()

        meta = {
            "tool": "CrossForge Native Crawler v1.0",
            "target": str(base),
            "crawl_stats": {
                "pages_fetched":        budget.pages_fetched,
                "forms_found":          self._forms_found,
                "js_files_analyzed":    self._js_files_analyzed,
                "js_files_truncated":   self._js_files_truncated,  # [Phase 1 rebuild bugfix]
                "endpoints_discovered": len(endpoints),
                "elapsed_seconds":      round(elapsed, 2),
                "final_page_budget":    budget.budget,
                "stopped_reason":       (
                    "stalled_yield" if budget.stalled else
                    "budget_exhausted" if not budget.has_room() else
                    "frontier_exhausted"
                ),
                "headless": headless_stats,
                # Phase 1 rebuild: quality-gate filter counts — how many
                # fetched pages were classified as junk and excluded from
                # discovery. See core/recon_quality.py.
                "quality_gate": (
                    dict(self._quality_baseline.stats) if self._quality_baseline else None
                ),
            },
            # Phase 1 rebuild: informational-only recon breadth results.
            # Never influenced candidate generation or crawl scope — see
            # each source module's docstring for why. Present here purely
            # for operator visibility / reporting.
            "recon_intel": {
                "subdomains": self._recon_intel["subdomains"],
                "dns": (
                    {h: vars(rs) for h, rs in self._recon_intel["dns"].items()}
                    if self._recon_intel["dns"] else None
                ),
                "wayback": self._recon_intel["wayback"],
            },
        }

        return {
            "endpoints": endpoints,
            "meta": meta,
            "target_response_headers": self._target_response_headers,
        }

    # ------------------------------------------------------------------
    # Headless rendering pass (optional — see module docstring)
    # ------------------------------------------------------------------

    async def _run_headless_pass(self, base_url: str, allowed_hosts: set[str]) -> dict:
        """
        Purely observational escalation for SPAs the static pass can't see
        into: render each seed page in a real headless Chromium, capture
        every network request the page issues *on its own* (this is what
        recovers endpoints built from runtime string concatenation, e.g.
        `fetch("/api/x?target=" + userInput)` — a static regex fundamentally
        cannot resolve that, but watching the actual outgoing request can),
        and harvest the final post-JS DOM for href/src/action. No form-fill,
        no clicking — see the "WHAT THE HEADLESS PASS DELIBERATELY DOES NOT
        DO" section in the module docstring for why.

        Returns a stats dict (always — never raises) so the caller can
        report exactly what happened, including a clear reason when this
        was skipped or failed, rather than silently doing nothing.
        """
        stats = {
            "attempted": False, "rendered_pages": 0,
            "network_requests_observed": 0, "new_endpoints": 0,
            "hash_routes_seen": 0, "skip_reason": None,
        }

        if not self.cfg.headless_enabled:
            stats["skip_reason"] = "disabled via config (crawl.headless_enabled: false)"
            return stats

        # BUG 5 FIX: The old condition `len(self._endpoints) >= headless_skip_if_endpoints_ge`
        # compared the RAW endpoint count (every path the crawler fetched, including
        # paramless SPA shell routes from sitemap/robots) against the threshold.
        # PROBLEM: A pure Angular/React SPA returns 18+ paramless shell routes from
        # its sitemap, so 18 >= 15 fires and headless is skipped — on exactly the
        # class of target where headless rendering is most needed (a JS-driven SPA
        # where every real endpoint/param is invisible to the static pass).
        # FIX: Count only endpoints that carry at least one param in any bucket.
        # Zero-param endpoints give us nothing to test regardless of how many
        # there are — what matters for the skip decision is whether we already
        # have enough TESTABLE surface to justify skipping the more expensive pass.
        endpoints_with_params = sum(
            1 for acc in self._endpoints.values()
            if any(
                acc.params_detail.get(b)
                for b in ("query", "form", "js", "multipart")
            )
        )
        if not self.cfg.headless_force and endpoints_with_params >= self.cfg.headless_skip_if_endpoints_ge:
            stats["skip_reason"] = (
                f"static crawl already found {endpoints_with_params} endpoints with params "
                f"(>= headless_skip_if_endpoints_ge={self.cfg.headless_skip_if_endpoints_ge}) — "
                f"set crawl.headless_force: true to always render"
            )
            return stats

        try:
            from playwright.async_api import async_playwright  # optional dependency
        except ImportError:
            stats["skip_reason"] = (
                "playwright not installed — "
                "pip install 'crossforge[render]' && playwright install chromium"
            )
            return stats

        stats["attempted"] = True
        before_count = len(self._endpoints)

        # Seed pages: base URL first, then up to N-1 more same-origin pages
        # the static pass already found (so the render budget goes to real
        # discovered pages, not just the homepage).
        extra_seeds = [u for u in self._visited_pages if u != _page_key(base_url)]
        seed_pages = [base_url] + extra_seeds[: max(0, self.cfg.headless_max_seed_pages - 1)]

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=self.cfg.user_agent,
                )

                for seed in seed_pages[: self.cfg.headless_max_seed_pages]:
                    if not _in_scope(seed, allowed_hosts):
                        continue
                    page = await context.new_page()

                    def _make_on_request(counter_stats):
                        def _on_request(req):
                            url = req.url
                            if _in_scope(url, allowed_hosts) and not _should_skip(url):
                                counter_stats["network_requests_observed"] += 1
                                # source_bucket="js": we only know the endpoint was
                                # called, not which param the app treats as a URL —
                                # same "let the existing filter decide" logic as the
                                # static JS pass (see _record_endpoint_from_url).
                                self._record_endpoint_from_url(
                                    url, req.method.upper(), None, source_bucket="js",
                                )
                        return _on_request

                    page.on("request", _make_on_request(stats))

                    if self.cfg.headless_block_resource_types:
                        blocked = set(self.cfg.headless_block_resource_types)

                        async def _route_filter(route):
                            try:
                                if route.request.resource_type in blocked:
                                    await route.abort()
                                else:
                                    await route.continue_()
                            except Exception:
                                pass
                        await page.route("**/*", _route_filter)

                    try:
                        await page.goto(seed, wait_until="networkidle",
                                         timeout=self.cfg.headless_timeout_ms)
                    except Exception:
                        # networkidle can legitimately never fire (long-poll,
                        # websocket keep-alive) — fall back to "loaded enough"
                        # rather than lose this page's data entirely.
                        try:
                            await page.wait_for_load_state("domcontentloaded", timeout=5000)
                        except Exception:
                            pass

                    try:
                        hrefs = await page.eval_on_selector_all(
                            "[href],[src],[action]",
                            "els => els.map(e => e.href || e.src || e.action).filter(Boolean)",
                        )
                        for h in hrefs:
                            abs_url = h if h.startswith(("http://", "https://")) else _resolve(seed, h)
                            if abs_url:
                                self._record_endpoint_from_url(abs_url, "GET", None)
                    except Exception:
                        pass

                    # ---- Hash-route navigation (SPA deep discovery) --------
                    # Previously this was "DISCOVERY only (informational)" —
                    # we counted hash routes seen in the JS source but never
                    # navigated to them. That left the most important API calls
                    # (the ones that only fire when a user is "on" a specific
                    # route) completely invisible.
                    # Now: extract hash routes from the loaded page's content
                    # and navigate to each one, capturing the XHR/fetch calls
                    # it fires. Each navigation is bounded by a short timeout
                    # so a broken or infinitely-loading route doesn't stall
                    # the entire headless pass.
                    # Safety: we navigate within the SAME page context so
                    # the same request-listener is already registered — no
                    # new listeners needed. We use page.evaluate to do a
                    # client-side hash change (window.location.hash = "#/x")
                    # rather than a full goto() to avoid triggering the
                    # browser's reload heuristics on same-origin hash changes.
                    hash_routes_discovered: set[str] = set()
                    try:
                        content = await page.content()
                        for m in re.finditer(
                            r"""["'`](#/[a-zA-Z0-9_\-/]{1,80})["'`]""", content
                        ):
                            hash_routes_discovered.add(m.group(1))
                        stats["hash_routes_seen"] += len(hash_routes_discovered)
                    except Exception:
                        pass

                    _MAX_HASH_ROUTES = 15   # cap per seed page to stay within time budget
                    for route in list(hash_routes_discovered)[:_MAX_HASH_ROUTES]:
                        try:
                            # Client-side navigation only — no full page reload.
                            await page.evaluate(
                                f"() => {{ window.location.hash = {repr(route)}; }}"
                            )
                            # Wait briefly for the route component to mount and
                            # fire its data-fetch calls. networkidle would be
                            # ideal but can hang; a short fixed wait is reliable.
                            try:
                                await page.wait_for_load_state(
                                    "networkidle", timeout=3000
                                )
                            except Exception:
                                import asyncio as _asyncio
                                await _asyncio.sleep(0.8)
                            # Harvest any new hrefs rendered into the DOM by
                            # this route's component.
                            try:
                                hrefs = await page.eval_on_selector_all(
                                    "[href],[src],[action]",
                                    "els => els.map(e => e.href || e.src || e.action).filter(Boolean)",
                                )
                                for h in hrefs:
                                    abs_url = (
                                        h if h.startswith(("http://", "https://"))
                                        else _resolve(seed, h)
                                    )
                                    if abs_url:
                                        self._record_endpoint_from_url(abs_url, "GET", None)
                            except Exception:
                                pass
                        except Exception:
                            pass

                    stats["rendered_pages"] += 1
                    await page.close()

                await context.close()
                await browser.close()
        except Exception as exc:
            stats["skip_reason"] = f"headless pass failed: {exc}"

        stats["new_endpoints"] = len(self._endpoints) - before_count
        return stats

    # ------------------------------------------------------------------
    # API Wordlist Probe
    # ------------------------------------------------------------------

    # Curated SSRF-relevant API paths drawn from the 25-category taxonomy.
    # Organised by category so it's easy to extend. Every entry is a
    # relative path. The probe is HEAD-first (fast, no body), falling back
    # to GET if HEAD returns 405. A 200/201/400/401/403/422 response means
    # the path EXISTS; 404/410 means it doesn't. 3xx responses to external
    # hosts also count as existing (redirect sink).
    _SSRF_WORDLIST: list[str] = [
        # Proxy / gateway
        "/proxy", "/api/proxy", "/gateway", "/forward", "/relay",
        "/api/forward", "/api/relay", "/route", "/dispatch",
        # Fetch / download
        "/fetch", "/api/fetch", "/download", "/api/download",
        "/get", "/api/get", "/retrieve", "/load",
        # Import / export
        "/import", "/api/import", "/api/v1/import", "/api/v2/import",
        "/ingest", "/upload", "/api/upload",
        # Preview / screenshot
        "/preview", "/api/preview", "/screenshot", "/api/screenshot",
        "/opengraph", "/og", "/api/og", "/unfurl", "/embed",
        "/link-preview", "/api/link-preview",
        # Image / media processing
        "/image", "/images", "/api/image", "/avatar", "/thumbnail",
        "/api/thumbnail", "/resize", "/convert", "/media",
        "/api/media", "/photo",
        # PDF / render
        "/pdf", "/api/pdf", "/render", "/api/render", "/print",
        "/html2pdf", "/api/html2pdf", "/report", "/api/report",
        "/invoice", "/api/invoice",
        # Webhook / callback
        "/webhook", "/api/webhook", "/webhooks", "/callback",
        "/api/callback", "/notify", "/api/notify", "/notification",
        "/hook", "/api/hook",
        # RSS / feed
        "/feed", "/rss", "/api/feed", "/api/rss", "/feeds",
        "/podcast", "/atom", "/sitemap",
        # REST API common patterns
        "/api/connect", "/connect", "/api/request",
        "/api/external", "/api/remote", "/api/v1/proxy",
        "/api/v1/fetch", "/api/v1/webhook", "/api/v1/preview",
        "/api/v2/proxy", "/api/v2/fetch",
        # Scan / crawl / monitor
        "/scan", "/api/scan", "/crawl", "/api/crawl",
        "/healthcheck", "/health", "/monitor", "/probe",
        # Redirect
        "/redirect", "/api/redirect", "/goto", "/go",
        # Backup / restore
        "/backup", "/restore", "/api/backup", "/api/restore",
        "/snapshot", "/archive",
        # Auth service URLs
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize", "/oauth/token", "/auth/callback",
        "/saml/metadata", "/api/auth/discovery",
        # Metadata / info
        "/metadata", "/api/metadata", "/meta", "/api/meta",
        "/info", "/api/info", "/favicon", "/api/favicon",
    ]

    async def _run_wordlist_probe(
        self, base_url: str, allowed_hosts: set[str],
    ) -> None:
        """
        HEAD-probe each path in _SSRF_WORDLIST against the target base.
        Paths that exist (non-404) are recorded as GET endpoints for
        prescore to evaluate — the same record call used everywhere else
        so they flow through identical downstream processing.
        """
        from urllib.parse import urljoin
        sem = asyncio.Semaphore(min(self.cfg.concurrency, 8))
        probed = self._SSRF_WORDLIST[: self.cfg.wordlist_probe_limit]

        async def _probe(path: str) -> None:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            if not _in_scope(url, allowed_hosts):
                return
            async with sem:
                try:
                    await self._limiter.acquire()
                    resp = await self._client.head(url)
                    status = resp.status_code
                except Exception:
                    try:
                        # HEAD not supported → try GET with a small timeout
                        await self._limiter.acquire()
                        resp = await self._client.get(url)
                        status = resp.status_code
                    except Exception:
                        return

                # 404/410 = doesn't exist; everything else = endpoint exists.
                # 401/403 means it exists but requires auth — still worth
                # recording because the scanner can detect the auth requirement
                # in Phase 1 baseline and the operator can re-run with --auth.
                if status not in (404, 410):
                    self._record_endpoint_from_url(url, "GET", status)

        await asyncio.gather(*[_probe(p) for p in probed], return_exceptions=True)

    # ------------------------------------------------------------------
    # Seeds
    # ------------------------------------------------------------------

    async def _collect_seeds(self, base: httpx.URL) -> list[str]:
        seeds: list[str] = []
        if not self.cfg.respect_robots_as_seed:
            return seeds
        try:
            resp = await self._client.get(str(base.join("/robots.txt")))
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            seeds.append(str(base.join(path)))
        except Exception:
            pass
        try:
            resp = await self._client.get(str(base.join("/sitemap.xml")))
            if resp.status_code == 200 and "<loc>" in resp.text.lower():
                for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text, re.IGNORECASE):
                    seeds.append(m.group(1))
        except Exception:
            pass

        # ---- Phase 1 rebuild: security.txt as an extra seed source -----
        # RFC 9116 security.txt commonly links a policy/contact URL that
        # points at exactly the kind of internal tooling (a vuln-disclosure
        # portal, a bounty-program API) worth having in the frontier. Same
        # trust model as robots/sitemap above — this is an authorised
        # assessment, so a path the target publishes is a legitimate seed.
        if self.cfg.respect_security_txt_as_seed:
            for path in ("/.well-known/security.txt", "/security.txt"):
                try:
                    resp = await self._client.get(str(base.join(path)))
                    if resp.status_code != 200:
                        continue
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if ":" not in line or line.startswith("#"):
                            continue
                        field_name, _, value = line.partition(":")
                        if field_name.strip().lower() in ("policy", "contact", "hiring"):
                            value = value.strip()
                            if value.startswith(("http://", "https://")):
                                seeds.append(value)
                    break  # first hit wins, don't fetch both well-known paths
                except Exception:
                    continue

        return seeds[:100]   # cap — sitemap.xml can be enormous on large sites

    # ------------------------------------------------------------------
    # Per-page fetch + parse
    # ------------------------------------------------------------------

    async def _fetch_and_parse(
        self, url: str, sem: asyncio.Semaphore,
    ) -> tuple[list[str], list[str]] | None:
        if _DESTRUCTIVE_PATH_RE.search(urllib.parse.urlsplit(url).path):
            return None  # [Safety-1] never fetched

        async with sem:
            await self._limiter.acquire()
            try:
                resp = await self._client.get(url)
            except Exception:
                return None

        if not self._target_response_headers and resp.headers:
            self._target_response_headers = dict(resp.headers)

        try:
            body = resp.text
        except Exception:
            body = ""

        # ---- Phase 1 rebuild: quality gate (core/recon_quality.py) ----
        # Classify BEFORE recording anything or parsing for links/forms/JS.
        # A soft-404/bot-block/duplicate-shell page contributes nothing —
        # recording it as an endpoint pollutes Phase 0's queue, and
        # "discovering" its links just re-adds more instances of the same
        # shell to the frontier. This still counts against the page
        # budget (the request already happened) but produces zero
        # downstream candidates or new frontier links.
        if self.cfg.quality_gate_enabled and self._quality_baseline is not None:
            verdict = recon_quality.classify_response(self._quality_baseline, resp.status_code, body)
            if verdict != recon_quality.QualityVerdict.REAL:
                return [], []

        self._record_endpoint_from_url(url, "GET", resp.status_code)

        content_type = resp.headers.get("content-type", "")
        if "html" not in content_type and not url.endswith((".html", "/", "")):
            return [], []

        if not body:
            return [], []

        parser = _PageParser()
        try:
            parser.feed(body)
        except Exception:
            return [], []

        page_base = url if not parser.base_href else str(httpx.URL(url).join(parser.base_href))
        discovered_links: list[str] = []

        for href in parser.links:
            abs_url = _resolve(page_base, href)
            if abs_url:
                discovered_links.append(abs_url)
                self._record_endpoint_from_url(abs_url, "GET", None)

        for form in parser.forms:
            self._forms_found += 1
            action_url = _resolve(page_base, form.action) if form.action else page_base
            if not action_url:
                continue
            if _DESTRUCTIVE_PATH_RE.search(urllib.parse.urlsplit(action_url).path):
                continue  # [Safety-1] don't even register destructive form actions as candidates
            # Phase 1 rebuild: multipart/form-data POST forms get their own
            # bucket (see _EndpointAccumulator + spider_adapter.py's
            # ParamLocation.BODY_MULTIPART routing) instead of collapsing
            # into "form" — a field like "avatar_url" or "import_document"
            # on a multipart upload form is a categorically different SSRF
            # sink (media-processing-triggered fetch) than the same field
            # name on a urlencoded form, and downstream context
            # classification should be able to tell them apart.
            if form.method == "GET":
                bucket = "query"
            elif form.enctype == "multipart/form-data":
                bucket = "multipart"
            else:
                bucket = "form"
            self._record_endpoint_fields(action_url, form.method, bucket, form.fields)

        if self.cfg.js_static_analysis:
            for src in parser.script_srcs:
                abs_js = _resolve(page_base, src)
                if abs_js and _in_scope(abs_js, {httpx.URL(url).host}):
                    await self._analyze_js_url(abs_js, page_base)
            for inline in parser.inline_js:
                self._analyze_js_text(inline, page_base)

        return discovered_links, []

    # ------------------------------------------------------------------
    # JS static analysis
    # ------------------------------------------------------------------

    async def _analyze_js_url(self, js_url: str, page_base: str) -> None:
        try:
            await self._limiter.acquire()
            resp = await self._client.get(js_url)
            if resp.status_code != 200:
                return
            text = resp.text
            # [Phase 1 rebuild bugfix] Previously: `if len(resp.content) >
            # max_js_bytes: return` — silently discarded the ENTIRE file
            # with no log line, no counter, nothing. Default cap was
            # 400_000 bytes, which is smaller than the single main app
            # bundle on most real SPA frameworks (Angular/React/Vue apps
            # commonly ship 500KB-3MB+ bundles even in production builds —
            # OWASP Juice Shop's own bundles regularly exceed this). The
            # practical effect: on exactly the class of app most likely to
            # have SSRF-relevant fetch/webhook/proxy calls buried in JS
            # (a client-heavy SPA), JS static analysis silently never ran
            # at all, and "0 JS files analyzed" gave no indication why.
            # Fix: analyze up to max_js_bytes of content instead of
            # skipping the file outright — regex/static analysis degrades
            # gracefully on a truncated string (it just won't see whatever
            # was past the cutoff), which is strictly better than seeing
            # nothing. The byte cap still exists and still matters (a
            # pathological multi-hundred-MB response shouldn't get a full
            # regex pass), it just no longer means "silently give up."
            truncated = len(resp.content) > self.cfg.max_js_bytes
            if truncated:
                # Truncate on the decoded text, not raw bytes, to avoid
                # cutting mid-multibyte-character.
                text = text[: self.cfg.max_js_bytes]
                self._js_files_truncated += 1
            self._js_files_analyzed += 1
            self._analyze_js_text(text, page_base)
        except Exception:
            pass

    def _analyze_js_text(self, text: str, page_base: str) -> None:
        found: set[str] = set()
        for pattern in _JS_ENDPOINT_PATTERNS:
            for m in pattern.finditer(text):
                found.add(m.group(1))
        for m in _JS_PATH_FALLBACK_RE.finditer(text):
            found.add(m.group(1))

        # ---- Phase 1 rebuild: JS variable/route-table depth ------------
        # Purely additive to the literal-string regex hits above — see
        # core/js_intel.py's module docstring for what this recovers that
        # the patterns above structurally cannot (variable-built URLs,
        # framework route tables, Next.js build manifests). Failures here
        # (a pathological/minified blob that trips something unexpected)
        # never take down JS analysis for the page — same
        # never-raise contract the rest of this method's regex passes
        # already have implicitly (regex matching doesn't throw on
        # arbitrary input, but this keeps the guarantee explicit now that
        # there's real parsing logic involved).
        try:
            found |= js_intel.enrich(text)
        except Exception:
            pass

        for raw in found:
            if raw.startswith(("http://", "https://")) or raw.startswith("/"):
                abs_url = _resolve(page_base, raw)
            else:
                continue
            if not abs_url or _should_skip(abs_url):
                continue
            self._record_endpoint_from_url(abs_url, "GET", None, source_bucket="js")

    # ------------------------------------------------------------------
    # Endpoint accumulation
    # ------------------------------------------------------------------

    def _record_endpoint_from_url(
        self, url: str, method: str, status: int | None, source_bucket: str | None = None,
    ) -> None:
        if _should_skip(url) or not _in_scope(url, self._allowed_hosts):
            return
        split = urllib.parse.urlsplit(url)
        path_key = urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        key = (path_key, method.upper())
        acc = self._endpoints.setdefault(key, _EndpointAccumulator(method=method.upper()))

        if status is not None:
            acc.observed_status.append(status)

        # NOTE: JS-discovered endpoints (source_bucket == "js") intentionally
        # get NO named param here — we only know the endpoint exists, not
        # what parameter carries a URL. Leaving params_detail empty means
        # spider_adapter._infer_ssrf_candidates() falls back to its
        # word-boundary path-keyword map (webhook/proxy/fetch/export/etc.)
        # for this endpoint — identical treatment to a spider-supplied
        # endpoint with no observed params. This is the SAME "don't blindly
        # trust every discovered path — only act on SSRF-plausible ones"
        # filtering the operator asked for; the crawler doesn't duplicate
        # that logic, it just feeds the existing filter.

        query = urllib.parse.parse_qs(split.query)
        for pname, pvals in query.items():
            acc.params_detail["query"].add(pname)
            acc.observed_values[pname] = pvals[0] if pvals else ""

    def _record_endpoint_fields(
        self, url: str, method: str, bucket: str, fields: list[str],
    ) -> None:
        if _should_skip(url) or not _in_scope(url, self._allowed_hosts):
            return
        split = urllib.parse.urlsplit(url)
        path_key = urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        key = (path_key, method.upper())
        acc = self._endpoints.setdefault(key, _EndpointAccumulator(method=method.upper()))
        for f in fields:
            acc.params_detail[bucket].add(f)
            acc.observed_values.setdefault(f, "")

    def _finalize_endpoints(self) -> list[dict]:
        out = []
        for (path_url, method), acc in self._endpoints.items():
            out.append({
                "url": path_url,
                "method": method,
                "params_detail": {
                    "query":     sorted(acc.params_detail.get("query", set())),
                    "form":      sorted(acc.params_detail.get("form", set())),
                    "js":        sorted(acc.params_detail.get("js", set())),
                    "multipart": sorted(acc.params_detail.get("multipart", set())),
                },
                "observed_values": acc.observed_values,
                "observed_status": acc.observed_status,
            })
        return out


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _resolve(base_url: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    try:
        return str(httpx.URL(base_url).join(href))
    except Exception:
        return None


def _in_scope(url: str, allowed_hosts: set[str]) -> bool:
    try:
        host = httpx.URL(url).host
    except Exception:
        return False
    return host in allowed_hosts


def _should_skip(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in _SKIP_EXTENSIONS:
        return True
    if _DESTRUCTIVE_PATH_RE.search(path):
        return True
    return False


def _page_key(url: str) -> str:
    """Dedup key: scheme+host+path (query variants merge into one page fetch,
    but their param NAMES are still recorded — see _record_endpoint_from_url)."""
    split = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((split.scheme, split.netloc, split.path.rstrip("/") or "/", "", ""))


# ---------------------------------------------------------------------------
# High-level convenience entry point used by agent.py
# ---------------------------------------------------------------------------

async def run_crawl(
    target_url: str,
    crawl_cfg: CrawlConfig,
    rate_limiter: RateLimiter | None = None,
    proxy: str | None = None,
    extra_headers: dict | None = None,
) -> dict:
    """
    Runs the native crawler and prints a console summary in the same
    phase-report style as the rest of the pipeline. Returns a Spider-format
    dict ready for core.loader / core.spider_adapter.
    """
    section("RECON — NATIVE CRAWL (no spider file supplied)")
    info(f"Target: {color(target_url, C.BCYAN)}")
    dim("No --input spider file given — CrossForge is crawling the target itself.")

    crawler = NativeCrawler(crawl_cfg, rate_limiter=rate_limiter, proxy=proxy, extra_headers=extra_headers)
    try:
        spider_data = await crawler.crawl(target_url)
    finally:
        await crawler.close()

    stats = spider_data["meta"]["crawl_stats"]
    ok(
        f"Crawl complete — {color(str(stats['pages_fetched']), C.BWHITE, C.BOLD)} pages, "
        f"{color(str(stats['forms_found']), C.BWHITE)} forms, "
        f"{color(str(stats['js_files_analyzed']), C.BWHITE)} JS files analyzed, "
        f"{color(str(stats['endpoints_discovered']), C.BWHITE, C.BOLD)} endpoints discovered "
        f"in {stats['elapsed_seconds']}s ({stats['stopped_reason']})"
    )
    # [Phase 1 rebuild bugfix] visibility for the truncate-not-drop fix —
    # an operator should be able to see when a bundle exceeded max_js_bytes
    # instead of that fact being invisible.
    if stats.get("js_files_truncated"):
        dim(f"{stats['js_files_truncated']} JS file(s) exceeded max_js_bytes "
            f"({crawl_cfg.max_js_bytes:,} bytes) and were analyzed truncated, not skipped")

    hl = stats.get("headless", {})
    if hl.get("attempted"):
        ok(
            f"Headless render pass — {color(str(hl['rendered_pages']), C.BWHITE)} page(s) rendered, "
            f"{color(str(hl['network_requests_observed']), C.BWHITE)} network requests observed, "
            f"{color(str(hl['new_endpoints']), C.BWHITE, C.BOLD)} additional endpoint(s), "
            f"{hl['hash_routes_seen']} client-side hash-route(s) seen (not auto-navigated)"
        )
    elif hl.get("skip_reason"):
        dim(f"Headless render pass skipped: {hl['skip_reason']}")

    # ---- Phase 1 rebuild: quality gate + recon intel summary ----------
    qg = stats.get("quality_gate")
    if qg and sum(qg.values()):
        dim(
            f"Quality gate filtered {qg['soft_404_filtered']} soft-404, "
            f"{qg['bot_blocked_filtered']} bot-blocked, "
            f"{qg['duplicate_shell_filtered']} duplicate-shell page(s) from discovery"
        )

    recon_intel = spider_data.get("recon_intel", {})
    sub = recon_intel.get("subdomains")
    if sub and sub.get("subdomains"):
        info(f"Subdomains found via crt.sh: {color(', '.join(sub['subdomains'][:8]), C.DIM)}"
             + (f" (+{len(sub['subdomains'])-8} more)" if len(sub['subdomains']) > 8 else ""))
    wb = recon_intel.get("wayback")
    if wb and wb.get("urls"):
        dim(f"Wayback Machine seeded {len(wb['urls'])} historical URL(s) into the crawl frontier")

    if stats["endpoints_discovered"] == 0:
        warn(
            "Crawler found 0 endpoints. If the target is a JavaScript-rendered "
            "SPA with no server-rendered links, static crawling under-reports — "
            "see LIMITATIONS in core/crawler.py. Try installing playwright for "
            "the headless render pass (pip install 'crossforge[render]' && "
            "playwright install chromium), or scope --crawl-scope wider."
        )
    tprint()
    return spider_data
