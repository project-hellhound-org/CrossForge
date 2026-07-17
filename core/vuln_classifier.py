"""
CrossForge SSRF Agent — SSRF Vulnerability Type Classifier
===========================================================
WHAT THIS MODULE DOES
----------------------
Takes a Candidate (endpoint + parameter pair) after prescore and assigns it
a precise VulnType label from the 25-category SSRF attack-surface taxonomy.
This runs as Phase 1.5 — after pre-score (which decides priority) but before
context classification (which selects payloads). VulnType feeds both
downstream phases:

  → context_classifier.py: uses VulnType to select the most precise payload
    subset instead of falling back to generic fetch_url payloads.

  → reporter.py: includes vuln_type in every JSON/SARIF finding so the
    operator knows not just "this is SSRF" but "this is an IMAGE_PROCESSING
    endpoint accepting a remote URL in a multipart form" — a different risk
    profile from "this is a MICROSERVICE_PROXY with a query-param URL sink".

WHY A SEPARATE MODULE FROM context_classifier.py
--------------------------------------------------
context_classifier.py answers "what payload strategy should we use?"
(FETCH_URL/REDIRECT/HOST_HEADER/...) — 7 coarse buckets optimised for
payload selection. vuln_classifier.py answers "what kind of SSRF surface
is this?" — 25 fine-grained categories optimised for reporting, severity
adjustment, and exploit routing. They're different questions. Keeping them
separate means neither has to compromise its classification granularity for
the other's use case.

CLASSIFIER ARCHITECTURE
------------------------
Three signal sources, each independently scored, highest-confidence wins:

  1. PARAMETER NAME signals — segment-normalised word matching against
     per-category param-name vocabularies. Most reliable single signal.

  2. ENDPOINT PATH signals — keyword matching against the URL path
     component. Combined with param signal for high-confidence results;
     used alone when the param name is generic.

  3. PARAM LOCATION + CONTENT TYPE signals — BODY_MULTIPART always narrows
     to MULTIPART_URL; BODY_JSON narrows to JSON_BODY_URL or GRAPHQL_MUTATION
     depending on body_template shape; HEADER narrows to HEADER_INJECTION.

No ML, no external calls. Deterministic, reproducible, O(n_patterns) per
candidate. Edge cases (two categories with equal confidence) break ties in
favour of the more specific category (IMAGE_PROCESSING over URL_PARAM for
example) using the explicit PRIORITY ordering at the bottom of this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from core.models import Candidate, VulnType, ParamLocation


# ===========================================================================
# Per-category signal vocabularies
# ===========================================================================

# Param-name segment words → category.
# Each tuple: (VulnType, confidence, frozenset_of_segment_words).
# A candidate matches when ANY segment of its param name (split on _ and -)
# appears in the word set.
_PARAM_RULES: list[tuple[VulnType, float, frozenset]] = [
    # --- Redirect/return sinks (checked before generic URL so return_to
    #     doesn't get classified as URL_PARAM)
    (VulnType.REDIRECT_PARAM, 0.92, frozenset({
        "redirect", "return", "next", "continue", "goto", "dest",
        "destination", "to", "forward", "location",
    })),
    # --- Webhook / callback
    (VulnType.CALLBACK_WEBHOOK, 0.91, frozenset({
        "webhook", "callback", "callbackurl", "notify", "notification",
        "ping", "hook", "listener", "eventurl", "postback", "ipn",
    })),
    # --- Feed / RSS readers
    (VulnType.FEED_RSS, 0.90, frozenset({
        "feed", "rss", "atom", "podcast", "sitemap", "manifest",
    })),
    # --- Auth service URLs (OAuth / OIDC / SAML / JWKS)
    (VulnType.AUTH_SERVICE, 0.92, frozenset({
        "jwks", "issuer", "discovery", "metadata", "openid",
        "saml", "idp", "oidc", "oauthurl", "authurl", "authorizationurl",
        "tokenurl", "userinfourl", "wellknown",
    })),
    # --- Cloud storage connectors
    (VulnType.CLOUD_STORAGE, 0.89, frozenset({
        "bucket", "s3", "blob", "gcs", "storageurl", "cloudurl",
        "dropbox", "drive", "onedrive", "sharepoint", "azure",
    })),
    # --- Image / avatar processing (before generic URL to be more specific)
    (VulnType.IMAGE_PROCESSING, 0.88, frozenset({
        "image", "img", "avatar", "photo", "picture", "pic",
        "thumbnail", "thumb", "logo", "icon", "cover", "banner",
        "screenshot", "capture", "ocr",
    })),
    # --- PDF / rendering services
    (VulnType.PDF_SERVICE, 0.88, frozenset({
        "pdf", "render", "html2pdf", "htmltopdf", "wkhtmltopdf",
        "puppeteer", "renderurl", "invoice", "report",
    })),
    # --- File / document import with remote URL
    (VulnType.FILE_IMPORT, 0.87, frozenset({
        "import", "upload", "ingest", "sync", "migrate",
        "restore", "recover", "cloneurl", "repourl", "git",
    })),
    # --- Multipart URL fields (image_url, avatar_url, document_url)
    # Detected by param location (BODY_MULTIPART) + these suffix words.
    (VulnType.MULTIPART_URL, 0.90, frozenset({
        # "url" segment in a multipart context is handled by location rule,
        # but these suffixes alone in multipart form are distinctive too.
        "imageurl", "avatarurl", "documenturl", "fileurl", "mediaurl",
    })),
    # --- Generic URL fetch (broad, lower priority than specifics above)
    (VulnType.URL_PARAM, 0.85, frozenset({
        "url", "uri", "link", "src", "source", "href",
        "endpoint", "host", "domain", "address", "server",
        "resource", "asset", "api", "service", "proxy",
        "fetch", "load", "download", "preview", "remote",
        "target", "baseurl", "apiurl", "serviceurl", "referer",
    })),
    # --- Backup / restore
    (VulnType.BACKUP_RESTORE, 0.87, frozenset({
        "backup", "snapshot", "restore", "archive", "mirror", "clone",
    })),
    # --- Video / media services
    (VulnType.VIDEO_SERVICE, 0.86, frozenset({
        "video", "youtube", "vimeo", "podcast", "stream",
        "mediaurl", "videoid", "thumburl",
    })),
    # --- Email template rendering
    (VulnType.EMAIL_TEMPLATE, 0.85, frozenset({
        "templateurl", "emailtemplate", "template", "emailsrc",
    })),
    # --- Plugin / package / extension install
    (VulnType.PACKAGE_IMPORT, 0.87, frozenset({
        "plugin", "extension", "package", "module", "addon",
        "repo", "repository", "registry", "packageurl",
    })),
    # --- Open graph / metadata / favicon / link preview
    (VulnType.METADATA_EXTRACTOR, 0.88, frozenset({
        "opengraph", "og", "favicon", "metadata", "meta",
        "linkpreview", "preview", "pageurl", "siteurl",
    })),
    # --- Crawl / monitor / scan
    (VulnType.CRAWL_MONITOR, 0.86, frozenset({
        "crawl", "scan", "monitor", "check", "healthcheck",
        "ping", "probe", "spider", "inspector",
    })),
]

# ---------------------------------------------------------------------------
# Endpoint path rules — keyword sets matched against URL path segments.
# Each tuple: (VulnType, confidence, frozenset_of_path_keywords).
# A path keyword matches if it appears as a complete path segment (/fetch/)
# OR as a prefix of one (/fetcher → "fetcher" starts with "fetch").
# ---------------------------------------------------------------------------
_PATH_RULES: list[tuple[VulnType, float, frozenset]] = [
    (VulnType.MICROSERVICE_PROXY, 0.93, frozenset({
        "proxy", "gateway", "forward", "route", "dispatch",
        "connect", "relay", "tunnel", "passthrough",
    })),
    (VulnType.URL_PREVIEW, 0.91, frozenset({
        "preview", "screenshot", "opengraph", "og", "metadata",
        "favicon", "thumbnail", "card", "embed", "unfurl",
    })),
    (VulnType.IMAGE_PROCESSING, 0.90, frozenset({
        "image", "images", "img", "avatar", "thumbnail",
        "resize", "crop", "convert", "ocr", "vision",
    })),
    (VulnType.PDF_SERVICE, 0.90, frozenset({
        "pdf", "render", "report", "export", "print",
        "html2pdf", "generate", "invoice",
    })),
    (VulnType.FILE_IMPORT, 0.89, frozenset({
        "import", "upload", "ingest", "sync", "restore",
        "migrate", "clone", "backup",
    })),
    (VulnType.CALLBACK_WEBHOOK, 0.91, frozenset({
        "webhook", "callback", "notify", "notification",
        "hook", "event", "ipn", "postback",
    })),
    (VulnType.FEED_RSS, 0.90, frozenset({
        "feed", "rss", "atom", "podcast", "subscribe",
    })),
    (VulnType.CRAWL_MONITOR, 0.89, frozenset({
        "crawl", "scan", "healthcheck", "health", "monitor",
        "check", "probe", "spider", "crawler",
    })),
    (VulnType.VIDEO_SERVICE, 0.88, frozenset({
        "video", "media", "stream", "player", "podcast",
    })),
    (VulnType.URL_PARAM, 0.80, frozenset({
        "fetch", "download", "get", "load", "request",
        "retrieve", "resolve", "lookup",
    })),
    (VulnType.BACKUP_RESTORE, 0.88, frozenset({
        "backup", "restore", "snapshot", "archive", "mirror",
    })),
    (VulnType.METADATA_EXTRACTOR, 0.89, frozenset({
        "metadata", "info", "details", "summary", "description",
        "opengraph", "og", "link-preview",
    })),
    (VulnType.EMAIL_TEMPLATE, 0.87, frozenset({
        "email", "mail", "template", "notification",
    })),
    (VulnType.PACKAGE_IMPORT, 0.88, frozenset({
        "install", "plugin", "extension", "package", "module",
        "addon", "marketplace", "registry",
    })),
    (VulnType.CLOUD_STORAGE, 0.88, frozenset({
        "storage", "s3", "blob", "bucket", "files", "drive",
    })),
    (VulnType.AUTH_SERVICE, 0.90, frozenset({
        "oauth", "oidc", "saml", "auth", "sso", "login",
        "token", "jwks", "openid", "identity",
    })),
]

# ---------------------------------------------------------------------------
# Header param names → HEADER_INJECTION
# ---------------------------------------------------------------------------
_SSRF_HEADERS: frozenset[str] = frozenset({
    "x-forwarded-host", "x-forwarded-for", "x-real-ip",
    "x-original-url", "x-rewrite-url", "x-custom-ip-authorization",
    "x-forwarded-server", "x-http-host-override",
    "forwarded", "x-forwarded", "x-remote-ip", "x-remote-addr",
    "referer", "origin", "host",
    "x-proxy-url", "x-target", "x-upstream",
})

# ---------------------------------------------------------------------------
# Tie-breaker priority: more-specific type wins when two rules tie on
# confidence. Lower number = higher priority.
# ---------------------------------------------------------------------------
_PRIORITY: dict[VulnType, int] = {
    VulnType.GRAPHQL_MUTATION:   0,
    VulnType.XML_EXTERNAL:       1,
    VulnType.MULTIPART_URL:      2,
    VulnType.AUTH_SERVICE:       3,
    VulnType.HEADER_INJECTION:   4,
    VulnType.MICROSERVICE_PROXY: 5,
    VulnType.IMAGE_PROCESSING:   6,
    VulnType.PDF_SERVICE:        6,
    VulnType.URL_PREVIEW:        7,
    VulnType.FILE_IMPORT:        7,
    VulnType.CALLBACK_WEBHOOK:   8,
    VulnType.FEED_RSS:           8,
    VulnType.REDIRECT_PARAM:     9,
    VulnType.BACKUP_RESTORE:     9,
    VulnType.VIDEO_SERVICE:      9,
    VulnType.CLOUD_STORAGE:      9,
    VulnType.CRAWL_MONITOR:      9,
    VulnType.EMAIL_TEMPLATE:     10,
    VulnType.PACKAGE_IMPORT:     10,
    VulnType.METADATA_EXTRACTOR: 10,
    VulnType.JSON_BODY_URL:      11,
    VulnType.NESTED_URL:         11,
    VulnType.GRPC_ENDPOINT:      11,
    VulnType.URL_PARAM:          12,
    VulnType.UNKNOWN:            99,
}

# Category display names for reporter
_CATEGORY_LABELS: dict[VulnType, str] = {
    VulnType.URL_PARAM:          "URL-Based Parameter",
    VulnType.REDIRECT_PARAM:     "Open Redirect / SSRF via Redirect",
    VulnType.CALLBACK_WEBHOOK:   "Webhook / Callback URL",
    VulnType.FEED_RSS:           "RSS / Feed Reader",
    VulnType.HEADER_INJECTION:   "Header Injection (Host/Forwarded)",
    VulnType.AUTH_SERVICE:       "Auth Service URL (OAuth/OIDC/SAML/JWKS)",
    VulnType.CLOUD_STORAGE:      "Cloud Storage Connector",
    VulnType.MICROSERVICE_PROXY: "Microservice Proxy / API Gateway",
    VulnType.URL_PREVIEW:        "URL Preview / Screenshot / OpenGraph",
    VulnType.IMAGE_PROCESSING:   "Image Processing Service",
    VulnType.PDF_SERVICE:        "PDF / HTML Render Service",
    VulnType.FILE_IMPORT:        "Remote File Import",
    VulnType.VIDEO_SERVICE:      "Video / Media Service",
    VulnType.BACKUP_RESTORE:     "Backup / Restore URL",
    VulnType.CRAWL_MONITOR:      "Crawler / Monitor / Healthcheck",
    VulnType.GRAPHQL_MUTATION:   "GraphQL Mutation with URL Argument",
    VulnType.XML_EXTERNAL:       "XML External Entity / SOAP URL",
    VulnType.MULTIPART_URL:      "Multipart Upload with URL Field",
    VulnType.JSON_BODY_URL:      "JSON Body URL Parameter",
    VulnType.NESTED_URL:         "Nested Object URL Parameter",
    VulnType.GRPC_ENDPOINT:      "gRPC Endpoint / Host Field",
    VulnType.EMAIL_TEMPLATE:     "Email Template / Notification URL",
    VulnType.PACKAGE_IMPORT:     "Plugin / Package Install URL",
    VulnType.METADATA_EXTRACTOR: "Metadata / OpenGraph Extractor",
    VulnType.UNKNOWN:            "Unknown SSRF Surface",
}


# ===========================================================================
# Helper: segment-normalise a param or path component
# ===========================================================================

def _segments(name: str) -> list[str]:
    """Split on underscores and hyphens, lower-case each part."""
    return [s.lower() for s in re.split(r"[_\-]", name) if s]


def _path_segments(url: str) -> list[str]:
    """Return lower-cased path components from a URL."""
    try:
        path = urlparse(url).path
    except Exception:
        path = url
    return [s.lower() for s in path.split("/") if s]


# ===========================================================================
# Core classification
# ===========================================================================

@dataclass
class ClassificationResult:
    vuln_type:   VulnType
    category:    str
    confidence:  float
    signals:     list[str]


def classify(candidate: Candidate) -> ClassificationResult:
    """
    Classify a Candidate into one of the 25 SSRF VulnType categories.
    Returns a ClassificationResult; never raises.
    """
    results: list[tuple[float, VulnType, list[str]]] = []

    param  = candidate.parameter
    url    = candidate.target_url
    loc    = candidate.param_location
    body   = candidate.body_template

    param_segs = _segments(param)
    path_segs  = _path_segments(url)

    # -----------------------------------------------------------------------
    # Rule 1 — Param location → type (highest-priority structural signal)
    # -----------------------------------------------------------------------
    if loc == ParamLocation.HEADER and param.lower() in _SSRF_HEADERS:
        results.append((0.96, VulnType.HEADER_INJECTION,
                        [f"header param {param!r} is a known SSRF-enabling routing header"]))

    if loc == ParamLocation.BODY_MULTIPART:
        # Any URL-shaped field in a multipart upload → MULTIPART_URL
        if any(s in _PARAM_RULES[-1][2] for s in param_segs):   # URL_PARAM words
            results.append((0.93, VulnType.MULTIPART_URL,
                            [f"param {param!r} in multipart/form-data upload form"]))
        else:
            results.append((0.78, VulnType.MULTIPART_URL,
                            ["multipart/form-data param — possible file-URL upload"]))

    if loc == ParamLocation.BODY_JSON and candidate.graphql_sourced:
        results.append((0.97, VulnType.GRAPHQL_MUTATION,
                        ["GraphQL introspection-sourced candidate"]))

    if loc == ParamLocation.BODY_JSON and not candidate.graphql_sourced:
        # Dotted path (nested.url) → NESTED_URL
        if "." in param:
            results.append((0.88, VulnType.NESTED_URL,
                            [f"nested JSON body param {param!r}"]))
        else:
            # Check body_template shape for URL-shaped fields
            if isinstance(body, dict) and _has_url_field(body):
                results.append((0.84, VulnType.JSON_BODY_URL,
                                ["JSON body with URL-shaped field in body_template"]))

    # -----------------------------------------------------------------------
    # Rule 2 — Param name segment matching
    # -----------------------------------------------------------------------
    for vtype, conf, words in _PARAM_RULES:
        if any(s in words for s in param_segs):
            signals = [f"param segment in {vtype.value} vocabulary (matched {param!r})"]
            results.append((conf, vtype, signals))

    # -----------------------------------------------------------------------
    # Rule 3 — Endpoint path segment matching
    # -----------------------------------------------------------------------
    for vtype, conf, keywords in _PATH_RULES:
        matched = [s for s in path_segs if any(s.startswith(k) for k in keywords)]
        if matched:
            signals = [f"path segment {matched[0]!r} matches {vtype.value} pattern"]
            # Path-only match is slightly weaker than param-name match
            results.append((conf * 0.85, vtype, signals))

    # -----------------------------------------------------------------------
    # Rule 4 — Observed value is a URL (strong but not sufficient alone)
    # -----------------------------------------------------------------------
    ov = candidate.original_value if isinstance(candidate.original_value, str) else ""
    if re.match(r"^(https?|ftp|gopher|file|dict)://", ov, re.I):
        results.append((0.75, VulnType.URL_PARAM,
                        [f"observed value is a URL: {ov[:60]!r}"]))

    # -----------------------------------------------------------------------
    # Rule 5 — Combined param + path (boost confidence when both agree)
    # -----------------------------------------------------------------------
    if len(results) >= 2:
        type_scores: dict[VulnType, float] = {}
        type_signals: dict[VulnType, list] = {}
        for conf, vt, sigs in results:
            if conf > type_scores.get(vt, 0.0):
                type_scores[vt] = conf
                type_signals[vt] = sigs
        # If two independent signal sources agree on the same type, boost
        for vt, conf in list(type_scores.items()):
            count = sum(1 for _, t, _ in results if t == vt)
            if count >= 2 and vt != VulnType.URL_PARAM:
                type_scores[vt] = min(0.99, conf + 0.05 * (count - 1))

    # -----------------------------------------------------------------------
    # Pick winner: highest confidence, tie-break by priority table
    # -----------------------------------------------------------------------
    if not results:
        return ClassificationResult(
            vuln_type=VulnType.UNKNOWN, category=_CATEGORY_LABELS[VulnType.UNKNOWN],
            confidence=0.0, signals=["no signals matched"],
        )

    best_conf = max(c for c, _, _ in results)
    candidates_at_best = [(c, t, s) for c, t, s in results if c >= best_conf - 0.01]
    _, winner, signals = min(
        candidates_at_best,
        key=lambda x: _PRIORITY.get(x[1], 99),
    )

    return ClassificationResult(
        vuln_type=winner,
        category=_CATEGORY_LABELS.get(winner, winner.value),
        confidence=round(best_conf, 2),
        signals=signals,
    )


def _has_url_field(body: dict) -> bool:
    """Shallow check: does any key in the dict look like a URL-param name?"""
    url_words = {"url", "uri", "link", "src", "endpoint", "callback", "webhook", "feed"}
    for k in body:
        segs = set(_segments(str(k)))
        if segs & url_words:
            return True
    return False


# ===========================================================================
# Public API: annotate a Candidate in-place
# ===========================================================================

def annotate(candidate: Candidate) -> Candidate:
    """
    Classify the candidate and set vuln_type, vuln_category, vuln_confidence.
    Modifies in-place, also returns it for chaining.
    Never raises — classification failure just leaves VulnType.UNKNOWN.
    """
    try:
        result = classify(candidate)
    except Exception:
        return candidate

    candidate.vuln_type       = result.vuln_type
    candidate.vuln_category   = result.category
    candidate.vuln_confidence = result.confidence
    return candidate


def annotate_batch(candidates: list[Candidate]) -> list[Candidate]:
    """Annotate a list in-place. Returns the same list."""
    for c in candidates:
        annotate(c)
    return candidates
