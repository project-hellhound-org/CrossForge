"""
HELLHOUND SSRF v5.0 - Phase 0: Surface Mapping & Candidate Pre-Scoring
========================================================================
v5 fixes:
  [P0-FIX] Word-boundary anchors on ALL HIGH_VALUE_ENDPOINT_PATTERNS
           Previously r"/test" matched "/pentesting", "/attest", "/contest".
           Now uses r"(?:^|/)test(?:/|$)" — path-component level matching.
  [P1-FIX] Blocked-header candidates receive a reduced pre_score and
           LOW tier regardless of other signals, preventing Phase 6
           from running on semantically invalid injection points.
  [v5-NEW] openapi_sourced candidates receive a +1.0 bonus — spec-derived
           candidates are known to exist and have correct parameter metadata.
  [v5-NEW] Infrastructure-noise flag propagated: if candidate.infra_noise_detected
           is already True (set by baseline.py), score is capped at 3.0 and
           a confidence_reduction_flag is added so Phase 4 doesn't over-promote.
"""

from __future__ import annotations
import re
from core.models import Candidate, ParamLocation, PreScoreTier

# ---------------------------------------------------------------------------
# Header injection blocklist (mirrored from http_client.py)
# ---------------------------------------------------------------------------

_BLOCKED_INJECTION_HEADERS: frozenset[str] = frozenset({
    "host", "content-length", "transfer-encoding", "accept-encoding",
    "content-encoding", "connection", "upgrade", "expect",
    "te", "trailer", "proxy-connection", "keep-alive",
})

# ---------------------------------------------------------------------------
# Param-name patterns — unchanged from v4, strong proven signal
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Param-name matching — segment-normalised lookup
# ---------------------------------------------------------------------------
# WHY NOT A SINGLE JOINED REGEX:
# re.search on joined patterns has two failure modes:
#   (a) Too broad: r"feed" matches "feedback", r"path" matches "xpath",
#       r"scan" matches "scanner" — noise params get falsely promoted.
#   (b) Too narrow: r"\bfeed\b" fails on "feed_url" because underscore IS a
#       \w character, so \b doesn't fire between "feed" and "_url". Real
#       SSRF-sink params like "image_url", "webhook_url", "callback_url"
#       all get missed.
# SOLUTION: Normalise the param name by splitting on _ and -, then check
# each segment against a frozenset of exact SSRF-sink words. A compound
# param like "image_url" splits to ["image", "url"] — both segments match.
# A noise param like "feedback" stays as one segment ["feedback"] — "feedback"
# is not in the set. "feed" the real param name IS in the set. Correct.

_HIGH_VALUE_PARAM_WORDS: frozenset[str] = frozenset({
    "url", "uri", "link", "src", "source", "target",
    "dest", "destination", "redirect", "return", "next", "to",
    "callback", "webhook", "feed", "endpoint", "host", "domain",
    "path", "file", "image", "avatar", "thumbnail", "proxy",
    "fetch", "load", "import", "export", "preview", "document",
    "pdf", "download", "location", "resource", "asset", "service",
    "server", "address", "addr", "notify", "ping",
    "check", "scan", "crawl", "manifest", "rss", "sitemap",
    "href", "action", "api",
})

# Keep the endpoint-level regex — endpoints are full path strings, not
# param names, so the word-boundary regex approach is correct there.
# Nothing changes for endpoint scoring.

def _param_score(name: str) -> bool:
    """
    Returns True if any underscore/hyphen segment of the param name is an
    exact SSRF-sink word. Case-insensitive.
    """
    segments = re.split(r"[_\-]", name.lower())
    return any(seg in _HIGH_VALUE_PARAM_WORDS for seg in segments)


# ---------------------------------------------------------------------------
# [P0-FIX] Endpoint patterns — word-boundary path-component anchors
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# [P0-FIX] Endpoint patterns — word-boundary path-component anchors
# ---------------------------------------------------------------------------
# Rule: r"(?:^|/)WORD(?:/|$)"  — matches /WORD or /prefix/WORD or /WORD/suffix
# This prevents "test" from matching "/pentesting", "export" from matching
# "/exportation", "ping" from matching "/settings", etc.
#
# Exception: r"/integrat" is a PREFIX match (integration/integrations) — this
# is intentional and correct; it's kept as a startswith pattern.

HIGH_VALUE_ENDPOINT_PATTERNS = [
    r"(?:^|/)proxy(?:/|$)",
    r"(?:^|/)fetch(?:/|$)",
    r"(?:^|/)preview(?:/|$)",
    r"(?:^|/)render(?:/|$)",
    r"(?:^|/)export(?:/|$)",
    r"(?:^|/)import(?:/|$)",
    r"(?:^|/)webhook(?:s)?(?:/|$)",
    r"(?:^|/)callback(?:/|$)",
    r"/integrat",                        # intentional prefix: integration(s)
    r"(?:^|/)oauth(?:/|$)",
    r"(?:^|/)sso(?:/|$)",
    r"(?:^|/)pdf(?:/|$)",
    r"(?:^|/)image(?:s)?(?:/|$)",
    r"(?:^|/)thumbnail(?:s)?(?:/|$)",
    r"(?:^|/)avatar(?:s)?(?:/|$)",
    r"(?:^|/)upload(?:s)?(?:/|$)",
    r"(?:^|/)notify(?:/|$)",
    r"(?:^|/)ping(?:/|$)",
    r"(?:^|/)health(?:/|$)",
    r"(?:^|/)screenshot(?:s)?(?:/|$)",
    r"(?:^|/)embed(?:/|$)",
    r"(?:^|/)feed(?:s)?(?:/|$)",
    r"(?:^|/)rss(?:/|$)",
    r"(?:^|/)sync(?:/|$)",
    r"(?:^|/)connector(?:s)?(?:/|$)",
    r"(?:^|/)download(?:s)?(?:/|$)",
    r"(?:^|/)resource(?:s)?(?:/|$)",
    r"(?:^|/)link(?:/|$)",
    r"(?:^|/)redirect(?:/|$)",
    r"(?:^|/)forward(?:/|$)",
    r"(?:^|/)load(?:/|$)",
    r"(?:^|/)check(?:/|$)",
]

# Content-Type signals
HIGH_VALUE_CONTENT_TYPES = [
    "application/pdf", "image/", "multipart/form-data",
]

# Param-location weights (unchanged)
LOCATION_WEIGHTS = {
    "body_json":      1.5,
    "body_form":      1.3,
    "body_multipart": 1.2,
    "query":          1.0,
    "header":         0.8,
    "cookie":         0.4,
    "path":           0.6,
}

# Compiled regexes (module-level — compiled once, reused everywhere)
# _HIGH_PARAM_RE removed — replaced by _param_score() above which uses
# segment-normalised lookup against _HIGH_VALUE_PARAM_WORDS frozenset.
_HIGH_ENDPOINT_RE = re.compile("|".join(HIGH_VALUE_ENDPOINT_PATTERNS), re.IGNORECASE)


def score_candidate(candidate: Candidate, response_content_type: str = "") -> Candidate:
    """
    Assigns candidate.pre_score (float 0-10) and candidate.pre_score_tier.
    Every contributing signal is logged to candidate.pre_score_reasons
    so the HUD and report can explain triage decisions.
    """
    score = 0.0
    reasons: list[str] = []

    # ---- [P1-FIX] Blocked-header fast-path --------------------------------
    # Header candidates whose parameter is in the blocklist are semantically
    # invalid injection points. Cap at LOW regardless of other signals.
    if (
        candidate.param_location == ParamLocation.HEADER
        and candidate.parameter.lower() in _BLOCKED_INJECTION_HEADERS
    ):
        candidate.pre_score = 0.0
        candidate.pre_score_tier = PreScoreTier.LOW
        candidate.pre_score_reasons = [
            f"header '{candidate.parameter}' is in the injection blocklist "
            "(protocol-level header — SSRF injection would produce malformed requests)"
        ]
        candidate.confidence_reduction_flags.append("header_blocklisted")
        return candidate

    # ---- [v5] Infra-noise cap ---------------------------------------------
    # If baseline.py already flagged this endpoint as infrastructure-noise
    # (same z-score anomaly pattern across ≥3 candidates), cap the score
    # so Phase 4 doesn't over-promote spurious anomalies.
    if candidate.infra_noise_detected:
        candidate.pre_score = 2.0
        candidate.pre_score_tier = PreScoreTier.LOW
        candidate.pre_score_reasons = ["infrastructure noise detected on endpoint — score capped"]
        candidate.confidence_reduction_flags.append("infra_noise")
        return candidate

    # ---- Signal 1: Parameter name (strongest single signal) ---------------
    if _param_score(candidate.parameter):
        score += 4.0
        reasons.append(
            f"parameter name '{candidate.parameter}' matches SSRF-sink pattern"
        )

    # ---- Signal 2: Endpoint path ------------------------------------------
    # Uses word-boundary regex — no more "test" matching "pentesting"
    path = _url_path(candidate.target_url)
    if _HIGH_ENDPOINT_RE.search(path):
        score += 3.0
        reasons.append(
            "endpoint path matches known SSRF-sink function "
            "(proxy/fetch/webhook/export/etc.)"
        )

    # ---- Signal 3: Value already looks like a URL -------------------------
    if isinstance(candidate.original_value, str) and re.match(
        r"^(https?|ftp|file|gopher|dict)://",
        candidate.original_value,
        re.IGNORECASE,
    ):
        score += 2.5
        reasons.append("original parameter value is itself a URL/URI")

    # ---- Signal 4: Response content-type ----------------------------------
    if any(ct in response_content_type.lower() for ct in HIGH_VALUE_CONTENT_TYPES):
        score += 1.0
        reasons.append(
            f"endpoint response content-type '{response_content_type}' indicates "
            "file-processing or rendering sink"
        )

    # ---- Signal 5: Location weight ----------------------------------------
    loc_weight = LOCATION_WEIGHTS.get(candidate.param_location.value, 1.0)
    score *= loc_weight
    if loc_weight != 1.0:
        reasons.append(
            f"parameter location '{candidate.param_location.value}' "
            f"weight ×{loc_weight}"
        )

    # ---- Signal 6: Method bonus -------------------------------------------
    if candidate.method.upper() in ("POST", "PUT", "PATCH"):
        score += 0.5
        reasons.append(
            f"method {candidate.method.upper()} commonly carries integration config"
        )

    # ---- [v5] OpenAPI-sourced bonus ---------------------------------------
    # Spec-derived candidates are definitively correct parameter metadata;
    # they deserve a slightly higher floor than heuristic candidates.
    if getattr(candidate, "openapi_sourced", False):
        score += 1.0
        reasons.append("parameter discovered via OpenAPI/Swagger spec (high-confidence metadata)")

    score = min(score, 10.0)

    if score >= 5.0:
        tier = PreScoreTier.HIGH
    elif score >= 2.0:
        tier = PreScoreTier.MEDIUM
    else:
        tier = PreScoreTier.LOW

    candidate.pre_score = round(score, 2)
    candidate.pre_score_tier = tier
    candidate.pre_score_reasons = reasons
    return candidate


def triage_queue(candidates: list[Candidate]) -> list[Candidate]:
    """
    Orders candidates HIGH → MEDIUM → LOW, highest score first within tier.
    Candidates with confidence_reduction_flags are deprioritised within their tier.
    """
    def sort_key(c: Candidate):
        tier_rank = {"high": 0, "medium": 1, "low": 2}.get(c.pre_score_tier.value, 2)
        penalty = len(c.confidence_reduction_flags) * 0.5
        return (tier_rank, -(c.pre_score - penalty))

    return sorted(candidates, key=sort_key)


def _url_path(url: str) -> str:
    """Extract just the path component for pattern matching."""
    try:
        import httpx
        return httpx.URL(url).path or "/"
    except Exception:
        # Fallback manual extraction
        after_scheme = url.split("://", 1)[-1]
        path = "/" + after_scheme.split("/", 1)[-1].split("?")[0] if "/" in after_scheme else "/"
        return path
