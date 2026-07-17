"""
CrossForge SSRF Agent — Spider JSON Adapter
============================================
v5.1 fixes applied to v5.0 bugs observed in the Juice Shop run:

  [FIX-1] HOST_HEADER candidates only for HIGH pre-score endpoints,
           not every endpoint. 7 headers × 35 endpoints = 245 noise
           candidates. Now limited to HIGH-tier SSRF sinks only.

  [FIX-2] Strict deduplication on (url, norm_method, parameter, location).
           Eliminates duplicates created when OpenAPI + Spider both discover
           the same param, or when two path-keyword patterns match.

  [FIX-3] Auth-redirect detection. When the spider records that an endpoint
           returned HTTP 302 on ALL methods, it is flagged `auth_required`.
           The adapter surfaces these so the agent can warn the operator
           instead of silently wasting budget on 302→/login loops.

  [FIX-4] Word-boundary path-keyword matching (retained from v5.0 prescore).

  [FIX-5] SSRF-relevance score filter. Candidates with pre_score == 0.0
           after scoring are dropped before returning — no more "username"
           or "page" parameters consuming Phase 1 budget.

  [FIX-6] HOST_HEADER parameter blocklist enforced at generation time.
           Routing headers (Host, Content-Length etc.) that are in the
           http_client blocklist are never generated as HOST_HEADER cands.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

from core.models import Candidate, ParamLocation
from core.prescore import score_candidate, triage_queue, _BLOCKED_INJECTION_HEADERS, _url_path
from core import vuln_classifier as _vc


# ---------------------------------------------------------------------------
# Word-boundary path → inferred parameter map  [FIX-4]
# ---------------------------------------------------------------------------
_PATH_SSRF_PARAM_MAP: dict[str, list[str]] = {
    "screenshot":        ["url", "target_url", "src"],
    "fetch":             ["url", "src", "target"],
    "opengraph":         ["url", "target"],
    "verify":            ["url", "callback_url", "endpoint"],
    "import-image":      ["url", "image_url", "src"],
    "rss":               ["url", "feed_url", "rss_url"],
    "export-pdf":        ["url", "source_url", "document_url"],
    "validate":          ["url", "endpoint", "target"],
    "cloud-metadata":    ["url", "metadata_url", "endpoint"],
    "service-discovery": ["url", "service_url", "target"],
    "external-check":    ["url", "check_url", "target"],
    "preview":           ["url", "target", "src"],
    "webhook":           ["url", "callback_url", "endpoint"],
    "connector":         ["url", "endpoint", "target"],
    "proxy":             ["url", "target", "src"],
    "redirect":          ["url", "next", "return_to", "dest"],
    "metadata":          ["url", "src", "target"],
    "integrations":      ["url", "endpoint", "target"],
    "health":            ["url", "target", "check_url"],
    "import":            ["url", "src", "image_url"],
    "download":          ["url", "file_url", "src"],
    "link":              ["url", "href", "target"],
    "embed":             ["url", "src", "target"],
    "thumbnail":         ["url", "image_url", "src"],
    "avatar":            ["url", "image_url", "src"],
    "pdf":               ["url", "source_url", "document_url"],
    "notify":            ["url", "callback_url", "endpoint"],
    "sync":              ["url", "endpoint", "target"],
    "feed":              ["url", "feed_url", "src"],
    "ping":              ["url", "target", "check_url"],
    "check":             ["url", "target", "endpoint"],
    "api-console":       ["url", "endpoint", "target"],
}

# Pre-compiled word-boundary regexes  [FIX-4]
_PATH_PATTERNS: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"(?:^|/)" + re.escape(kw) + r"(?:/|$)", re.IGNORECASE), params)
    for kw, params in _PATH_SSRF_PARAM_MAP.items()
]

# Host-header SSRF candidates — generated only for HIGH-tier endpoints [FIX-1]
# Subset of the full 7 — most impactful routing headers only
_HOST_HEADER_TARGETS = [
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
]

# Non-SSRF endpoint path patterns — skip entirely.
# [FIX-7, discovered during crawler integration testing] "register"/"signup"
# used to be matched ANYWHERE in the path via .search(), which silently
# dropped genuinely SSRF-relevant endpoints like /webhook/register,
# /integrations/register, and /oauth/clients/register (RFC 7591 dynamic
# client registration — whose redirect_uris field is a documented
# real-world SSRF/open-redirect vector). A user-signup path is called
# /register or /auth/register, not /webhook/register — so these two
# keywords are now anchored to the START of the path with _NON_SSRF_PREFIX_RE
# instead of matching as a substring anywhere. The other keywords here
# (login, logout, password reset, csrf, static assets, etc.) are safe to
# keep as anywhere-in-path matches — there's no equivalent "webhook/logout"
# pattern in the wild that would need to survive this filter.
_NON_SSRF_PATH_RE = re.compile(
    r"/(login|logout|password|reset|csrf|token|"
    r"oauth/callback|auth/callback|static/|favicon|\.well-known)($|/)",
    re.IGNORECASE,
)
_NON_SSRF_PREFIX_RE = re.compile(r"^/(register|signup)($|/)", re.IGNORECASE)

# Credential-bearing response header patterns
_CRED_HEADER_RE = re.compile(
    r"(credential|secret|password|api.?key|token|auth)", re.IGNORECASE
)


@dataclass
class AdaptResult:
    candidates:             list[Candidate]
    skipped_urls:           list[str]
    leaked_credentials:     list[dict]
    method_corrected_urls:  list[str]
    auth_required_urls:     list[str]   # [FIX-3] endpoints that 302→login
    total_before_filter:    int
    total_after_filter:     int
    # [Phase 1 rebuild bugfix] Separate, correctly-scoped counters. Prior to
    # this, total_before_filter (measured right after per-endpoint expansion)
    # was diffed against total_after_filter (measured after zero-score
    # filtering *and* HOST_HEADER candidate synthesis *and* dedup) as if
    # both were the same pipeline stage. HOST_HEADER synthesis is additive,
    # not a filter — when it added more candidates than zero-score filtering
    # removed, that subtraction went negative (observed in the field as
    # "Filtered -11 zero-score candidate(s)" and "37 raw → 48 after filter",
    # which is not a rounding quirk, it's the actual arithmetic of net growth
    # across a step the log line never accounted for). Each stage below is
    # counted at the point it actually happens, so the numbers can never
    # produce a nonsensical negative delta again — see loader.py's summary.
    zero_score_dropped:     int = 0
    host_header_added:      int = 0
    dedup_dropped:          int = 0


def detect_spider_format(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    return isinstance(data.get("endpoints"), list) and isinstance(data.get("meta"), dict)


def adapt(
    spider_data: dict,
    generate_host_header_candidates: bool = True,
    host_header_min_tier: str = "high",   # [FIX-1] only for HIGH endpoints
) -> AdaptResult:
    """
    Convert Spider JSON → Candidates with all v5.1 fixes applied.
    """
    candidates_raw: list[Candidate] = []
    skipped:        list[str]       = []
    method_fixed:   list[str]       = []
    leaked_creds:   list[dict]      = []
    auth_required:  list[str]       = []

    # BUG 6 FIX: Scope guard — reject endpoints whose host doesn't match the
    # declared target. The spider's meta.target is the source of truth.
    # When a spider follows an external redirect (e.g. /redirect → github.com)
    # and then crawls a few pages there, those external endpoints appear in the
    # spider file. We must not probe them — they're out of scope and probing
    # them during an engagement authorised only for the original target is a
    # serious boundary violation. Operators who explicitly want multi-host
    # coverage should configure extra_scope_hosts.
    target_meta = spider_data.get("meta", {})
    target_raw  = target_meta.get("target", "")
    try:
        _target_host = urlparse(target_raw).netloc if target_raw else None
    except Exception:
        _target_host = None

    global_headers = spider_data.get("target_response_headers", {})
    _extract_leaked_credentials(global_headers, leaked_creds)

    for endpoint in spider_data.get("endpoints", []):
        url = endpoint.get("url", "")
        if not url:
            continue

        # BUG 6 FIX: Skip out-of-scope hosts.
        if _target_host:
            ep_host = urlparse(url).netloc if "://" in url else None
            if ep_host and ep_host != _target_host:
                skipped.append(url)
                continue

        # [FIX-3] Auth-redirect detection
        if _is_auth_required(endpoint):
            auth_required.append(url)
            # still add but flag — agent will warn and may skip

        method, was_corrected = _correct_method(endpoint)
        if was_corrected:
            method_fixed.append(url)

        request_headers = _safe_request_headers(global_headers)
        params_detail   = endpoint.get("params_detail", {})
        has_params      = any(
            # [Phase 1 rebuild] "multipart" added — purely additive: any
            # spider file (native-crawl or externally supplied) without a
            # "multipart" key behaves exactly as before, since
            # params_detail.get(b) on a missing key returns None/falsy.
            params_detail.get(b)
            for b in ("query", "form", "js", "openapi", "runtime", "multipart")
        )

        excluded = _NON_SSRF_PATH_RE.search(url) or _NON_SSRF_PREFIX_RE.match(_url_path(url))

        new: list[Candidate] = []
        if has_params and not excluded:
            new = _expand_endpoint(endpoint, method, request_headers)
        elif not excluded:
            new = _infer_ssrf_candidates(endpoint, method, request_headers)

        if not new:
            skipped.append(url)

        candidates_raw.extend(new)

    total_before = len(candidates_raw)

    # Phase 0 pre-score all candidates
    for c in candidates_raw:
        score_candidate(c)

    # [FIX-5] Drop zero-score candidates (no SSRF signal at all)
    scored = [c for c in candidates_raw if c.pre_score > 0.0]
    zero_score_dropped = total_before - len(scored)   # [Phase 1 rebuild bugfix] measured right here, nowhere else

    # [FIX-1] HOST_HEADER candidates — only for HIGH-scoring endpoints
    host_header_added = 0
    if generate_host_header_candidates:
        pre_synthesis_count = len(scored)
        for c in scored:
            if c.pre_score_tier.value == host_header_min_tier:
                for hdr in _HOST_HEADER_TARGETS:
                    # [FIX-6] Skip if in http_client injection blocklist
                    if hdr.lower() in _BLOCKED_INJECTION_HEADERS:
                        continue
                    hh = Candidate(
                        target_url=c.target_url,
                        method=c.method,
                        parameter=hdr,
                        param_location=ParamLocation.HEADER,
                        original_value="",
                        headers=dict(c.headers),
                        cookies={},
                    )
                    scored.append(hh)
        # Re-score HOST_HEADER candidates
        for c in scored:
            if c.param_location == ParamLocation.HEADER and not c.pre_score:
                score_candidate(c)
        # [Phase 1 rebuild bugfix] This is a genuinely additive stage — track
        # it as its own number instead of letting it silently offset
        # zero_score_dropped above.
        host_header_added = len(scored) - pre_synthesis_count

    # [FIX-2] Strict deduplication
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Candidate] = []
    for c in scored:
        key = (
            c.target_url.rstrip("/"),
            c.method.upper(),
            c.parameter.lower(),
            c.param_location.value,
        )
        if key not in seen:
            seen.add(key)
            unique.append(c)
    dedup_dropped = len(scored) - len(unique)   # [Phase 1 rebuild bugfix]

    final = triage_queue(unique)

    # Phase 1.5: SSRF vuln-type classification on every passing candidate.
    # Runs here, after prescore filtering (so we only classify real candidates,
    # not noise that was dropped) and before returning to agent.py (so every
    # downstream phase — context_classifier, reporter, evidence_engine — can
    # read vuln_type without needing to import vuln_classifier themselves).
    _vc.annotate_batch(final)

    return AdaptResult(
        candidates=final,
        skipped_urls=skipped,
        leaked_credentials=leaked_creds,
        method_corrected_urls=method_fixed,
        auth_required_urls=auth_required,
        total_before_filter=total_before,
        total_after_filter=len(final),
        zero_score_dropped=zero_score_dropped,
        host_header_added=host_header_added,
        dedup_dropped=dedup_dropped,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _expand_endpoint(
    endpoint: dict,
    method: str,
    request_headers: dict,
) -> list[Candidate]:
    raw_url       = endpoint.get("url", "")
    params_detail = endpoint.get("params_detail", {})
    observed_vals = endpoint.get("observed_values", {}) or {}

    # BUG 4 FIX: Strip the existing query string from target_url for QUERY
    # candidates, then reconstruct it from the known param values.
    # PROBLEM: The spider stores the full observed URL including query params
    # in endpoint["url"] — e.g. "/redirect?to=https://github.com/...".
    # When _inject() adds params['to'] = payload_value, httpx appends it
    # to the existing ?to= already in the URL → duplicate param in the request.
    # FIX: base_url is scheme+host+path only. Each QUERY candidate's injection
    # uses that clean base, so httpx sees exactly ONE value per param.
    # Non-tested query params (other params already in the URL that we're not
    # injecting) are preserved in baseline_query_params and merged into the
    # probe so the server context is correct.
    parsed = urlparse(raw_url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    existing_query_params: dict[str, str] = {
        k: v for k, v in parse_qsl(parsed.query, keep_blank_values=True)
    }

    # BUG 2 FIX: Cross-domain form field pollution.
    # PROBLEM: When a spider follows a redirect to an external domain (e.g.
    # localhost:3000/redirect → github.com), it scrapes github.com's HTML
    # forms and attributes those fields back to the localhost endpoint.
    # This produces candidates like POST localhost:3000/redirect with
    # param=feedback (a GitHub search form field, score 9.6) — completely
    # wrong endpoint/param pairing.
    # FIX: For form/body/multipart buckets, only accept params that are either:
    #   (a) confirmed in form_fields_detail (the spider's own form-scrape output), OR
    #   (b) have a non-empty observed_value from the same-origin page.
    # We use form_fields_detail as the ground truth for what fields actually
    # exist on this endpoint's own page. If it's absent (older spider formats),
    # we fall back to accepting all — safer than losing real candidates.
    own_form_fields: set[str] | None = None
    form_fields_detail = endpoint.get("form_fields_detail")
    if isinstance(form_fields_detail, list) and form_fields_detail:
        own_form_fields = {f["name"] for f in form_fields_detail if f.get("name")}

    candidates: list[Candidate] = []

    bucket_location = {
        "query":     ParamLocation.QUERY,
        "form":      ParamLocation.BODY_FORM,
        "js":        ParamLocation.BODY_JSON,
        "openapi":   ParamLocation.BODY_JSON,
        "runtime":   ParamLocation.BODY_JSON,
        "multipart": ParamLocation.BODY_MULTIPART,
    }

    # Build all_params for body_template construction: unwrap list values.
    all_params: dict[str, str] = {}
    for bucket in bucket_location:
        for p in params_detail.get(bucket) or []:
            # BUG 1 FIX: Hellhound Spider stores observed_values as lists.
            # Unwrap to a single string here — all downstream code (prescore
            # Signal 3, http_client._inject, reporter PoC) expects str.
            all_params[p] = _unwrap_observed_value(observed_vals.get(p, ""))

    for bucket, location in bucket_location.items():
        eff_method = "POST" if location != ParamLocation.QUERY else method
        for param in params_detail.get(bucket) or []:

            # BUG 2 FIX: Skip cross-domain-polluted form fields.
            # For form/body buckets, if we have form_fields_detail from the
            # spider, only accept params that appear there. Query params and
            # JS/openapi/runtime buckets are never polluted this way (they
            # come from URL query strings or spec analysis, not form scraping).
            if (location in (ParamLocation.BODY_FORM, ParamLocation.BODY_MULTIPART)
                    and own_form_fields is not None
                    and param not in own_form_fields):
                continue  # this param came from a followed-redirect page, not this endpoint

            observed = _unwrap_observed_value(observed_vals.get(param, ""))

            if location == ParamLocation.QUERY:
                # BUG 4 FIX: Use clean base_url (no existing query string).
                # Restore the OTHER existing query params as context, but NOT
                # the one we're injecting — that slot is for the payload.
                context_params = {
                    k: v for k, v in existing_query_params.items()
                    if k != param
                }
                # body_template for QUERY = None (params go in URL, not body).
                # We store context_params in a separate field so baseline.py
                # can send the endpoint in its natural observed state.
                body_template = None
                cand_url = base_url
            else:
                body_template = (
                    dict(all_params) if location != ParamLocation.QUERY else None
                )
                cand_url = raw_url
                context_params = {}

            c = Candidate(
                target_url=cand_url,
                method=eff_method,
                parameter=param,
                param_location=location,
                original_value=observed,
                headers=dict(request_headers),
                cookies={},
                body_template=body_template,
            )
            # Store context params so baseline/probe can include them correctly.
            # Using a custom attribute — this is additive and ignored by modules
            # that don't know about it.
            if context_params:
                c.baseline_query_context = context_params
            candidates.append(c)

    return candidates


def _is_auth_required(endpoint: dict) -> bool:
    """
    [FIX-3] Heuristic: endpoint is auth-gated if all observed status codes
    are 302 (redirect-to-login). Spider JSON may record `observed_status`.
    """
    statuses = endpoint.get("observed_status", [])
    if not statuses:
        return False
    return all(s == 302 for s in statuses)


def _infer_ssrf_candidates(
    endpoint: dict,
    method: str,
    request_headers: dict,
) -> list[Candidate]:
    """
    [FIX-4] Word-boundary regex matching for inferred candidates.
    Only generates candidates for parameters that score > 0 via prescore.
    """
    url = endpoint.get("url", "")
    try:
        import httpx as _hx
        path = _hx.URL(url).path or "/"
    except Exception:
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1] if "://" in url else url

    inferred: list[str] = []
    for pattern, params in _PATH_PATTERNS:
        if pattern.search(path):
            for p in params:
                if p not in inferred:
                    inferred.append(p)

    if not inferred:
        return []

    location      = ParamLocation.BODY_JSON if method.upper() == "POST" else ParamLocation.QUERY
    candidates: list[Candidate] = []
    for param in inferred:
        body_template = (
            {param: ""} if location == ParamLocation.BODY_JSON else None
        )
        candidates.append(Candidate(
            target_url=url,
            method=method,
            parameter=param,
            param_location=location,
            original_value="",
            headers=dict(request_headers),
            cookies={},
            body_template=body_template,
        ))
    return candidates


def _unwrap_observed_value(raw) -> str:
    """
    Hellhound Spider v13.x stores observed_values as {param: [v1, v2, ...]} — a
    list of every value seen for that param across observed requests. CrossForge
    needs a single string: the most representative (first) value.
    When raw is already a string (older spider formats, OpenAPI adapter), pass through.
    When raw is a list, take the first element and stringify it.
    When raw is None or empty, return "".
    This is the ONLY place list→string unwrapping happens — all downstream code
    can safely assume original_value is str after this.
    """
    if isinstance(raw, list):
        return str(raw[0]) if raw else ""
    if isinstance(raw, str):
        return raw
    if raw is None:
        return ""
    return str(raw)
    """
    [FIX-3] Heuristic: endpoint is auth-gated if all observed status codes
    are 302 (redirect-to-login). Spider JSON may record `observed_status`.
    """
    statuses = endpoint.get("observed_status", [])
    if not statuses:
        return False
    return all(s == 302 for s in statuses)


def _correct_method(endpoint: dict) -> tuple[str, bool]:
    method            = (endpoint.get("method") or "GET").upper()
    observed_statuses = endpoint.get("observed_status", [])
    if method == "GET" and 405 in observed_statuses and 200 not in observed_statuses:
        return "POST", True
    return method, False


def _safe_request_headers(response_headers: dict) -> dict:
    _SKIP = {
        "server", "date", "content-length", "transfer-encoding",
        "connection", "vary", "set-cookie", "x-demo-credentials",
        "x-cloudsync-auth", "x-cloudsync-region", "x-cloudsync-version",
        "x-login-fields", "x-request-id", "x-ratelimit-limit",
        "x-ratelimit-remaining",
    }
    return {
        k: v for k, v in response_headers.items()
        if (k.lower() not in _SKIP
            and "credential" not in k.lower()
            and "secret"     not in k.lower()
            and "password"   not in k.lower())
    }


def _extract_leaked_credentials(headers: dict, out: list[dict]) -> None:
    for header_name, header_value in headers.items():
        if _CRED_HEADER_RE.search(header_name):
            out.append({
                "header": header_name,
                "value":  header_value,
                "note":   "Credential-like value detected in Spider response headers.",
            })
