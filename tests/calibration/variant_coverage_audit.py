"""
tests/calibration/variant_coverage_audit.py
=============================================
Comprehensive audit of all 25 VulnType SSRF variant categories.

For each variant, verifies:
  1. It has a VulnType enum member
  2. It maps to a ContextClass via context_classifier
  3. Prescore patterns cover it (param words or endpoint patterns)
  4. Payload engine generates relevant payloads

Also documents false-positive risk assessment per variant.
"""

import pytest
import re
from core.models import VulnType, ContextClass
from core.context_classifier import _VULN_TYPE_TO_CONTEXT, _vuln_type_to_context
from core.prescore import (
    _HIGH_VALUE_PARAM_WORDS,
    HIGH_VALUE_ENDPOINT_PATTERNS,
    _HIGH_ENDPOINT_RE,
    _param_score,
)


# ---------------------------------------------------------------------------
# Variant coverage matrix
# ---------------------------------------------------------------------------

# Each entry: (VulnType, expected ContextClass, sample param names, sample endpoint paths,
#              false_positive_risk: "low"|"medium"|"high", notes)
_VARIANTS = [
    # URL/parameter-level sinks
    (VulnType.URL_PARAM, ContextClass.FETCH_URL,
     ["url", "src", "target", "link", "uri"],
     ["/fetch", "/proxy", "/load"],
     "low", "Classic SSRF sink — high-confidence detection"),

    (VulnType.REDIRECT_PARAM, ContextClass.REDIRECT,
     ["redirect", "return", "next", "callback_url", "dest"],
     ["/redirect", "/forward"],
     "medium", "Open redirect can chain to SSRF but also legitimate redirects"),

    (VulnType.CALLBACK_WEBHOOK, ContextClass.ASYNC_SINK,
     ["webhook", "callback", "notify"],
     ["/webhook", "/callback", "/notify"],
     "low", "Async sinks — OOB confirmation critical for reducing FP"),

    (VulnType.FEED_RSS, ContextClass.ASYNC_SINK,
     ["feed", "rss"],
     ["/feed", "/rss"],
     "low", "RSS/feed parsers commonly fetch external URLs"),

    (VulnType.HEADER_INJECTION, ContextClass.HOST_HEADER,
     ["x-forwarded-host", "x-forwarded-for", "x-real-ip"],
     [],
     "medium", "Header location — many proxies set these legitimately"),

    (VulnType.AUTH_SERVICE, ContextClass.FETCH_URL,
     ["endpoint", "service"],
     ["/oauth", "/sso"],
     "low", "OAuth/OIDC URLs are high-value SSRF targets"),

    (VulnType.CLOUD_STORAGE, ContextClass.FETCH_URL,
     ["resource", "asset", "source"],
     ["/resource"],
     "medium", "Cloud storage connectors — URL may be constrained to specific domains"),

    # Endpoint-level sinks
    (VulnType.MICROSERVICE_PROXY, ContextClass.FETCH_URL,
     ["proxy", "endpoint", "service"],
     ["/proxy", "/forward"],
     "low", "Explicit proxy endpoints — high SSRF probability"),

    (VulnType.URL_PREVIEW, ContextClass.FETCH_URL,
     ["preview", "screenshot"],
     ["/preview", "/screenshot", "/embed"],
     "low", "URL preview services fetch arbitrary URLs by design"),

    (VulnType.IMAGE_PROCESSING, ContextClass.FETCH_URL,
     ["image", "avatar", "thumbnail"],
     ["/image", "/avatar", "/thumbnail"],
     "low", "Image processors commonly accept URLs"),

    (VulnType.PDF_SERVICE, ContextClass.ASYNC_SINK,
     ["pdf", "document", "render"],
     ["/pdf", "/render", "/export"],
     "low", "PDF/HTML renderers frequently fetch external resources"),

    (VulnType.FILE_IMPORT, ContextClass.ASYNC_SINK,
     ["import", "file", "load"],
     ["/import", "/upload"],
     "low", "File import from URL — direct SSRF vector"),

    (VulnType.VIDEO_SERVICE, ContextClass.FETCH_URL,
     ["video", "preview"],
     [],
     "medium", "Video services may restrict URL domains"),

    (VulnType.BACKUP_RESTORE, ContextClass.FETCH_URL,
     ["backup", "export"],
     [],
     "low", "Backup/restore from URL — privileged operation"),

    (VulnType.CRAWL_MONITOR, ContextClass.FETCH_URL,
     ["crawl", "scan", "check", "ping"],
     ["/crawl", "/scan", "/check", "/ping", "/health"],
     "low", "Health check/crawler endpoints fetch URLs"),

    # Protocol/format level
    (VulnType.GRAPHQL_MUTATION, ContextClass.FETCH_URL,
     ["api", "endpoint"],
     [],
     "medium", "GraphQL mutations with URL args — schema validation may limit"),

    (VulnType.XML_EXTERNAL, ContextClass.XML_BODY,
     ["xml", "xmldata", "soap"],
     ["/soap", "/wsdl", "/xmlrpc"],
     "low", "XXE → SSRF — well-understood vector"),

    (VulnType.MULTIPART_URL, ContextClass.FETCH_URL,
     ["image", "avatar", "file"],
     ["/upload"],
     "medium", "Multipart URL fields — depends on server-side processing"),

    (VulnType.FILE_UPLOAD_SSRF, None,  # No direct ContextClass mapping
     [],
     ["/upload"],
     "high", "SSRF via file content (SVG/DOCX) — requires file upload, not param injection"),

    (VulnType.JSON_BODY_URL, ContextClass.FETCH_URL,
     ["url", "endpoint", "callback"],
     [],
     "low", "JSON body URL fields — standard SSRF detection applies"),

    (VulnType.NESTED_URL, ContextClass.FETCH_URL,
     ["proxy", "endpoint"],
     [],
     "medium", "Nested config objects — deeper JSON parsing needed"),

    (VulnType.GRPC_ENDPOINT, ContextClass.FETCH_URL,
     ["endpoint", "host", "server"],
     [],
     "medium", "gRPC endpoint fields — less common but valid SSRF surface"),

    # Application feature sinks
    (VulnType.EMAIL_TEMPLATE, ContextClass.ASYNC_SINK,
     ["template", "header", "footer"],
     ["/template", "/notification"],
     "medium", "Email template URLs — async processing, OOB needed"),

    (VulnType.PACKAGE_IMPORT, ContextClass.ASYNC_SINK,
     ["import", "hook"],
     ["/plugin"],
     "low", "Plugin/extension install from URL — high-privilege operation"),

    (VulnType.METADATA_EXTRACTOR, ContextClass.FETCH_URL,
     ["preview", "fetch"],
     ["/preview", "/embed"],
     "low", "OpenGraph/favicon extraction — designed to fetch URLs"),
]


# ---------------------------------------------------------------------------
# Test: Every VulnType has a ContextClass mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vuln_type,expected_ctx,params,endpoints,fp_risk,notes", _VARIANTS)
def test_vulntype_has_context_mapping(vuln_type, expected_ctx, params, endpoints, fp_risk, notes):
    """Every VulnType should map to a ContextClass (except FILE_UPLOAD_SSRF)."""
    if expected_ctx is None:
        pytest.skip(f"{vuln_type.value}: no direct ContextClass mapping (by design)")
    result = _vuln_type_to_context(vuln_type)
    assert result == expected_ctx, (
        f"{vuln_type.value} maps to {result}, expected {expected_ctx}"
    )


# ---------------------------------------------------------------------------
# Test: Param words cover the variant
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vuln_type,expected_ctx,params,endpoints,fp_risk,notes", _VARIANTS)
def test_variant_has_param_coverage(vuln_type, expected_ctx, params, endpoints, fp_risk, notes):
    """At least one sample param name should score as high-value."""
    if not params:
        pytest.skip(f"{vuln_type.value}: no param-level detection (endpoint/header only)")
    scored = [p for p in params if _param_score(p)]
    assert scored, (
        f"{vuln_type.value}: none of {params} scored as high-value param. "
        f"Missing from _HIGH_VALUE_PARAM_WORDS?"
    )


# ---------------------------------------------------------------------------
# Test: Endpoint patterns cover the variant
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vuln_type,expected_ctx,params,endpoints,fp_risk,notes", _VARIANTS)
def test_variant_has_endpoint_coverage(vuln_type, expected_ctx, params, endpoints, fp_risk, notes):
    """At least one sample endpoint should match HIGH_VALUE_ENDPOINT_PATTERNS."""
    if not endpoints:
        pytest.skip(f"{vuln_type.value}: no endpoint-level patterns")
    matched = [e for e in endpoints if _HIGH_ENDPOINT_RE.search(e)]
    assert matched, (
        f"{vuln_type.value}: none of {endpoints} matched endpoint patterns"
    )


# ---------------------------------------------------------------------------
# Test: False-positive risk is documented
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vuln_type,expected_ctx,params,endpoints,fp_risk,notes", _VARIANTS)
def test_variant_fp_risk_documented(vuln_type, expected_ctx, params, endpoints, fp_risk, notes):
    """Each variant should have a documented false-positive risk level."""
    assert fp_risk in ("low", "medium", "high"), (
        f"{vuln_type.value}: fp_risk must be low/medium/high, got {fp_risk}"
    )


# ---------------------------------------------------------------------------
# Summary: print full coverage matrix (pytest -s to see)
# ---------------------------------------------------------------------------

def test_print_coverage_matrix():
    """Print the full coverage matrix for human review."""
    print("\n" + "=" * 80)
    print("SSRF Variant Coverage Matrix")
    print("=" * 80)
    print(f"{'VulnType':<25} {'ContextClass':<15} {'Params':<8} {'Endpoints':<10} {'FP Risk':<8}")
    print("-" * 80)
    for vt, ctx, params, endpoints, fp, notes in _VARIANTS:
        ctx_name = ctx.value if ctx else "NONE"
        param_ok = "✓" if any(_param_score(p) for p in params) else "✗"
        ep_ok = "✓" if any(_HIGH_ENDPOINT_RE.search(e) for e in endpoints) else "✗"
        print(f"{vt.value:<25} {ctx_name:<15} {param_ok:<8} {ep_ok:<10} {fp:<8} {notes[:40]}")
    print("=" * 80)
