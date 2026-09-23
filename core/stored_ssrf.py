"""
RAVAGER SSRF v2.0.0 — Stored / Second-Order SSRF Detection
================================================================
Detects SSRF that fires asynchronously after the initial request.

Stored SSRF scenarios:
  - Webhook registration: POST /webhooks → server fetches URL later
  - PDF rendering: Submit URL → background job renders → fetch
  - Email templates: Set URL in template → server fetches on send
  - File import: Provide URL → import job fetches on schedule
  - RSS/feed processing: Submit feed URL → background parser fetches

Detection approach:
  1. During Phase 2, classify candidates with ASYNC_SINK context
  2. During Phase 4, inject OOB tokens into async sink parameters
  3. After Phase 5 (main scan OOB poll), the OOB daemon continues polling
  4. Late-arriving callbacks are correlated with candidates
  5. Findings are upgraded to FIRM tier with 'stored_ssrf' VulnType

This module provides:
  - Async sink parameter/endpoint classification
  - Stored SSRF payload generators (embed OOB tokens in async-appropriate formats)
  - Finding upgrade logic for late callbacks
"""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import Candidate, Finding

logger = logging.getLogger(__name__)


# Parameters that commonly accept URLs for async processing
ASYNC_SINK_PARAMS = frozenset({
    # Webhooks
    "webhook_url", "callback_url", "notify_url", "hook_url",
    "webhook", "callback", "notification_url", "ping_url",
    # Templates
    "template_url", "template_src", "logo_url", "header_image",
    "footer_image", "background_url",
    # Import/export
    "import_url", "source_url", "feed_url", "rss_url",
    "atom_url", "podcast_url", "csv_url", "data_url",
    # PDF/document generation
    "pdf_url", "render_url", "screenshot_url", "print_url",
    "html_url", "document_url",
    # Integration
    "slack_webhook", "discord_webhook", "teams_webhook",
    "integration_url", "endpoint_url",
})

# URL path patterns that suggest async processing
ASYNC_SINK_PATHS = frozenset({
    "/webhooks", "/hooks", "/callbacks", "/integrations",
    "/subscribe", "/feeds", "/rss", "/import",
    "/export", "/render", "/pdf", "/screenshot",
    "/notify", "/notifications", "/templates",
    "/connectors", "/plugins",
})


def is_async_sink(candidate: "Candidate") -> bool:
    """
    Determine if a candidate parameter is likely an async SSRF sink.

    Returns True if the parameter name or endpoint URL suggests the
    submitted URL will be fetched asynchronously (not in the request
    lifecycle).
    """
    # Check parameter name
    param_lower = (candidate.parameter or "").lower()
    if param_lower in ASYNC_SINK_PARAMS:
        return True

    # Check for partial matches (e.g. 'my_webhook_url')
    for sink_param in ASYNC_SINK_PARAMS:
        if sink_param in param_lower:
            return True

    # Check URL path
    url_lower = candidate.target_url.lower()
    for path in ASYNC_SINK_PATHS:
        if path in url_lower:
            return True

    return False


def build_stored_ssrf_payloads(
    oob_token: str,
    collab_host: str,
) -> list[dict]:
    """
    Build payloads optimized for stored/async SSRF detection.

    These are standard OOB URLs but formatted for contexts where the
    URL may be stored and fetched later (webhooks, templates, feeds).

    Returns list of dicts with 'payload', 'technique', 'category' keys.
    """
    base_url = f"http://{oob_token}.{collab_host}"

    payloads: list[dict] = []

    # Standard HTTP callback
    payloads.append({
        "payload": f"{base_url}/stored-ssrf-check",
        "technique": "stored_http_callback",
        "category": "stored_ssrf",
    })

    # HTTPS variant (some async fetchers only do HTTPS)
    payloads.append({
        "payload": f"https://{oob_token}.{collab_host}/stored-ssrf-check",
        "technique": "stored_https_callback",
        "category": "stored_ssrf",
    })

    # DNS-only (for scenarios where HTTP is blocked but DNS resolves)
    payloads.append({
        "payload": f"http://{oob_token}.{collab_host}/",
        "technique": "stored_dns_callback",
        "category": "stored_ssrf",
    })

    return payloads


def upgrade_finding_for_stored_ssrf(
    finding: "Finding",
    delay_seconds: float,
    callback_protocol: str = "http",
) -> None:
    """
    Upgrade a finding when a stored SSRF callback is received.

    Called by the OOB daemon when a late-arriving interaction is
    correlated with a candidate.
    """
    finding.details["stored_ssrf"] = {
        "callback_delay_seconds": round(delay_seconds, 1),
        "callback_protocol": callback_protocol,
        "classification": "stored_second_order_ssrf",
        "description": (
            f"Stored SSRF confirmed: OOB callback received {delay_seconds:.1f}s "
            f"after initial injection via {callback_protocol.upper()} protocol. "
            f"The target application stored the URL and fetched it asynchronously."
        ),
    }
    # Upgrade severity if it was tentative
    if finding.confidence_tier in ("TENTATIVE", "HEURISTIC"):
        finding.confidence_tier = "FIRM"
        finding.confidence = 0.85
    finding.vuln_type = "stored_ssrf"
    logger.info(
        "Finding %s upgraded to FIRM (stored SSRF, %.1fs delay)",
        finding.finding_id[:8] if hasattr(finding, "finding_id") else "unknown",
        delay_seconds,
    )
