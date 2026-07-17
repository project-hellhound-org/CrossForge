"""
HELLHOUND SSRF v5.0 - SPA Catch-All Detector
===============================================
WHY THIS MODULE EXISTS
-----------------------
React / Vue / Angular SPAs use catch-all client-side routing that returns
HTTP 200 for EVERY path, including /totally-random-garbage-abc123. When
HELLHOUND's Phase 6 evidence engine runs build_port_state_map(), it uses
the SSRF sink to probe http://target:PORT/ — but if the app is a SPA, the
catch-all 200 is returned regardless of whether any backend connection was
made. Every port appears "open_http", inflating port_state_map artifacts
with schema_matched=True — the #1 source of false CERTAIN findings.

FIX: Before port-state mapping, probe 3 random 40-char paths via the
same SSRF sink. 2/3 returning 200 → SPA catch-all confirmed → skip
port_state_map entirely, only use cloud_metadata and protocol_banner
evidence types (which require schema marker matching, not just 200 OK).

This is distinct from the httpx-based random-path probing used by the
direct HTTP check — the SPA probe deliberately routes through the SSRF
parameter so we're testing what the backend receives, not the edge.
"""

from __future__ import annotations
import random
import string
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SPADetectionResult:
    is_catchall: bool
    confidence: float          # 0.0 - 1.0
    hits: int                  # how many random paths returned 200
    total_probes: int
    reason: str


async def detect_spa_catchall(
    http_client,
    candidate,
    probe_count: int = 3,
    path_length: int = 40,
) -> SPADetectionResult:
    """
    Sends `probe_count` requests injecting random-path URLs into `candidate`.
    If 2/3 (or more) return HTTP 200, the target is flagged as a SPA catch-all.

    IMPORTANT: uses the SSRF parameter itself, so we're testing what the
    backend resolves — not a direct HTTP check on the same host.

    Parameters
    ----------
    http_client : HttpClient
        The v5 http_client instance.
    candidate : Candidate
        The candidate whose parameter will carry the random-path probe URL.
    probe_count : int
        Number of random paths to probe (default 3).
    path_length : int
        Length of the random path segment (default 40 chars).

    Returns
    -------
    SPADetectionResult
    """
    base_url = _extract_base_url(candidate.target_url)
    hits = 0

    for i in range(probe_count):
        rand_path = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=path_length)
        )
        probe_url = f"{base_url}/{rand_path}"

        try:
            result = await http_client.send(
                candidate,
                payload_value=probe_url,
                payload_category="spa_catchall_probe",
            )
            if result.status_code == 200:
                hits += 1
                logger.debug(
                    "SPA probe hit 200: %s → %s (hit %d/%d)",
                    candidate.candidate_id[:8], probe_url, hits, probe_count,
                )
        except Exception as exc:
            logger.debug("SPA probe error on %s: %s", candidate.candidate_id[:8], exc)

    threshold = max(2, int(probe_count * 0.67))  # 2/3 of probes
    is_catchall = hits >= threshold
    confidence = hits / probe_count

    if is_catchall:
        reason = (
            f"{hits}/{probe_count} random-path probes returned HTTP 200 via the SSRF "
            f"parameter — SPA catch-all routing confirmed. Port-state map suppressed."
        )
        logger.info(
            "SPA catch-all detected for candidate %s (%s): %d/%d hits",
            candidate.candidate_id[:8], candidate.parameter, hits, probe_count,
        )
    else:
        reason = (
            f"Only {hits}/{probe_count} random-path probes hit 200 — not a catch-all."
        )

    return SPADetectionResult(
        is_catchall=is_catchall,
        confidence=confidence,
        hits=hits,
        total_probes=probe_count,
        reason=reason,
    )


def _extract_base_url(url: str) -> str:
    """Strips path/query from a URL to get just scheme://host:port."""
    try:
        import httpx
        u = httpx.URL(url)
        return f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")
    except Exception:
        # Fallback: manual split
        parts = url.split("://", 1)
        if len(parts) == 2:
            host_part = parts[1].split("/")[0]
            return f"{parts[0]}://{host_part}"
        return url
