"""
HELLHOUND SSRF v5.0 - Phase 2: Contextual Classification
===========================================================
v5 additions:
  [v5-NEW] CRLF_INJECTION context class — detected when parameter name/value
           suggests a redirect or header-value injection sink (the same vector
           that enables SSRF via Host header injection or response splitting).
  [v5-NEW] HOST_HEADER context class — triggered for candidates whose
           param_location is HEADER and parameter name is one of the
           SSRF-enabling routing headers (X-Forwarded-Host, X-Forwarded-For,
           X-Real-IP, etc.).
  [P0-FIX] blocked-header candidates (pre_score_tier already LOW from
           prescore.py) produce a single-entry subset containing only the
           generic OOB canary — minimal budget on invalid injection points.
"""

from __future__ import annotations
import json
import re
from pathlib import Path

from core.models import Candidate, ContextClass, ParamLocation, PreScoreTier, VulnType

# ---------------------------------------------------------------------------
# VulnType → ContextClass bridge
# ---------------------------------------------------------------------------
# When vuln_classifier.py has already assigned a confident VulnType, we
# translate it to the nearest ContextClass so the existing payload-selection
# logic (which keys on ContextClass) picks the right payload subset without
# needing to re-classify from scratch.
_VULN_TYPE_TO_CONTEXT: dict[str, ContextClass] = {
    "url_param":          ContextClass.FETCH_URL,
    "callback_webhook":   ContextClass.FETCH_URL,
    "feed_rss":           ContextClass.FETCH_URL,
    "microservice_proxy": ContextClass.FETCH_URL,
    "url_preview":        ContextClass.FETCH_URL,
    "image_processing":   ContextClass.FETCH_URL,
    "pdf_service":        ContextClass.FETCH_URL,
    "file_import":        ContextClass.FETCH_URL,
    "video_service":      ContextClass.FETCH_URL,
    "backup_restore":     ContextClass.FETCH_URL,
    "crawl_monitor":      ContextClass.FETCH_URL,
    "json_body_url":      ContextClass.FETCH_URL,
    "multipart_url":      ContextClass.FETCH_URL,
    "nested_url":         ContextClass.FETCH_URL,
    "graphql_mutation":   ContextClass.FETCH_URL,
    "cloud_storage":      ContextClass.FETCH_URL,
    "auth_service":       ContextClass.FETCH_URL,
    "metadata_extractor": ContextClass.FETCH_URL,
    "email_template":     ContextClass.FETCH_URL,
    "package_import":     ContextClass.FETCH_URL,
    "xml_external":       ContextClass.FETCH_URL,
    "grpc_endpoint":      ContextClass.FETCH_URL,
    # Redirect keeps its own ContextClass so it gets redirect-specific payloads
    "redirect_param":     ContextClass.REDIRECT,
    # Header injection keeps HOST_HEADER
    "header_injection":   ContextClass.HOST_HEADER,
}


def _vuln_type_to_context(vt: VulnType) -> ContextClass | None:
    return _VULN_TYPE_TO_CONTEXT.get(vt.value)

_PAYLOAD_PATH = Path(__file__).parent / "payloads" / "contextual_payloads.json"
with open(_PAYLOAD_PATH) as f:
    _CONTEXTUAL_PAYLOADS: dict = json.load(f)


# ---------------------------------------------------------------------------
# Classification regexes — priority order matters
# ---------------------------------------------------------------------------

# SSRF-enabling routing/proxy headers (Host header SSRF context)
_HOST_HEADER_PARAMS = frozenset({
    "x-forwarded-host",
    "x-forwarded-for",
    "x-real-ip",
    "x-original-url",
    "x-rewrite-url",
    "x-custom-ip-authorization",
    "x-forwarded-server",
    "x-http-host-override",
    "forwarded",
    "x-forwarded",
    "x-remote-ip",
    "x-remote-addr",
})

_REDIRECT_RE = re.compile(
    r"redirect|return(_to)?|next|continue|callback_?url|goto|dest(ination)?",
    re.I,
)
_CRLF_RE = re.compile(
    r"(?:header|h(?:dr)?|inject|split|location|cr(?:lf)?)",
    re.I,
)
_FILE_RE = re.compile(
    r"file|path|template|include|page|doc(?:ument)?|attachment|report|load",
    re.I,
)
_VALIDATOR_RE = re.compile(
    r"validate|verify|check|allow(?:ed)?|whitelist|allowlist|filter",
    re.I,
)
_FETCH_RE = re.compile(
    r"url|uri|src|source|webhook|feed|image|avatar|thumbnail|proxy|fetch|"
    r"endpoint|host|domain|import|preview|api_?url|service_?url|resource|"
    r"asset|download|link|href|manifest|sitemap|rss|notify(?:_url)?|"
    r"callback|ping|check|scan|crawl",
    re.I,
)

_MEDIUM_SUBSET_SIZE = 4
_LOW_SUBSET_SIZE    = 2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_context(candidate: Candidate) -> Candidate:
    """
    Sets candidate.context_class, context_confidence and payload_subset.
    If vuln_type was already set by vuln_classifier.py, uses it to derive
    a more precise ContextClass (avoids generic UNKNOWN for many cases that
    vuln_classifier already resolved to a specific attack surface type).
    """
    # Fast path: vuln_classifier already ran and has a confident result.
    # Map VulnType → ContextClass for the cases where the mapping is clear.
    if candidate.vuln_type.value != "unknown" and candidate.vuln_confidence >= 0.75:
        ctx = _vuln_type_to_context(candidate.vuln_type)
        if ctx is not None:
            candidate.context_class      = ctx
            candidate.context_confidence = candidate.vuln_confidence
            candidate.payload_subset     = _select_subset(ctx, candidate.pre_score_tier)
            return candidate

    name  = candidate.parameter
    value = candidate.original_value if isinstance(candidate.original_value, str) else ""
    loc   = candidate.param_location

    context, confidence = _classify(name, value, loc)
    candidate.context_class      = context
    candidate.context_confidence = confidence
    candidate.payload_subset     = _select_subset(context, candidate.pre_score_tier)
    return candidate


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def _classify(
    name: str,
    value: str,
    loc: ParamLocation,
) -> tuple[ContextClass, float]:

    # ---- HOST_HEADER: header-location candidates with routing-header names --
    if loc == ParamLocation.HEADER and name.lower() in _HOST_HEADER_PARAMS:
        return ContextClass.HOST_HEADER, 0.92

    # ---- REDIRECT: redirect / goto / return_to style params ----------------
    if _REDIRECT_RE.search(name):
        return ContextClass.REDIRECT, 0.85

    # ---- CRLF_INJECTION: header-injection / split sinks --------------------
    # Value or name contains %0d%0a, \r\n, or a header-injection keyword
    if (_CRLF_RE.search(name)
            or "%0d%0a" in value.lower()
            or "\\r\\n" in value
            or "\r\n" in value):
        return ContextClass.CRLF_INJECTION, 0.80

    # ---- FILE_INCLUDE: file path / include param ---------------------------
    if _FILE_RE.search(name) and (
        value.startswith("/") or "." in value or value == ""
    ):
        return ContextClass.FILE_INCLUDE, 0.75

    # ---- VALIDATOR: allow-list / URL-validation bypass ---------------------
    if _VALIDATOR_RE.search(name):
        return ContextClass.VALIDATOR, 0.70

    # ---- FETCH_URL: explicit fetch/proxy/webhook ---------------------------
    if _FETCH_RE.search(name) or re.match(r"^(https?|ftp|gopher|dict)://", value, re.I):
        return ContextClass.FETCH_URL, 0.90

    # ---- Value-shape fallback: bare URL in value ---------------------------
    if re.match(r"^(https?|ftp)://", value, re.I):
        return ContextClass.FETCH_URL, 0.60

    return ContextClass.UNKNOWN, 0.30


# ---------------------------------------------------------------------------
# Payload subset selection
# ---------------------------------------------------------------------------

def _select_subset(context: ContextClass, tier: PreScoreTier) -> list[dict]:
    full = list(
        _CONTEXTUAL_PAYLOADS.get(context.value,
        _CONTEXTUAL_PAYLOADS["unknown"])
    )

    if tier == PreScoreTier.HIGH:
        return full

    if tier == PreScoreTier.MEDIUM:
        return _prioritized(full)[:_MEDIUM_SUBSET_SIZE]

    # LOW tier: just the highest-yield generic probes (loopback + OOB canary)
    generic = _CONTEXTUAL_PAYLOADS["unknown"]
    return _prioritized(generic)[:_LOW_SUBSET_SIZE]


def _prioritized(payloads: list[dict]) -> list[dict]:
    """
    Orders payload list by expected diagnostic value per request.
    OOB canaries and cloud-metadata probes first, then loopback, then rest.
    """
    priority = {
        "oob_canary": 0,
        "generic_oob": 0,
        "cloud_metadata": 1,
        "generic_metadata": 1,
        "internal_loopback": 2,
        "generic_loopback": 2,
    }
    return sorted(payloads, key=lambda p: priority.get(p.get("category", ""), 5))
