"""
CrossForge SSRF Agent — Wayback Machine Seeding (Phase 1 addition, opt-in)
================================================================================
WHY THIS MODULE EXISTS
------------------------
core/crawler.py only ever sees paths that are LINKED somewhere in the
target's current HTML/JS/sitemap. A deprecated-but-still-live endpoint
that was delinked from the UI months ago (a legacy `/api/v1/fetch-url`
superseded by `/api/v2/...` but never actually decommissioned server-side)
is invisible to a live crawl — but the Wayback Machine's CDX index may
still remember it was linked at some point in the site's history.

This queries archive.org's CDX API for every URL it has ever indexed under
the target's domain, filtered down to same-origin (never adds an
out-of-scope host as a seed — same [Safety-2] principle as everywhere else
in the crawler) and handed back as extra crawl-frontier seeds, identical
in kind to the existing robots.txt/sitemap.xml seeds.

WHY THIS IS OPT-IN (config: crawl.wayback_enabled, default false)
------------------------------------------------------------------------
Two reasons, unlike DNS intel which defaults on:
  1. Third-party dependency (archive.org) outside the operator's and the
     target's control — a slow or unavailable CDX API shouldn't be able to
     stall or degrade a scan the operator didn't ask to depend on it.
  2. Historical URLs can be stale enough to be actively misleading —
     seeding a frontier with URLs from a since-decommissioned subsystem
     wastes probe budget on 404s. Worth having available, not worth
     defaulting on.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import quote

import httpx

logger = logging.getLogger("crossforge.wayback_probe")

_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={query}&output=json&fl=original&collapse=urlkey&limit={limit}"
)


async def fetch_historical_urls(
    domain: str,
    client: httpx.AsyncClient | None = None,
    timeout: float = 15.0,
    limit: int = 200,
) -> dict:
    """
    Returns {"urls": [...], "queried": bool, "skip_reason": str|None}.
    Never raises — a Wayback failure degrades to an empty result, it never
    aborts the crawl that's optionally using it as a seed source.
    """
    result = {"urls": [], "queried": False, "skip_reason": None}

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True)

    try:
        url = _CDX_URL.format(query=quote(f"{domain}/*"), limit=limit)
        try:
            resp = await client.get(url)
        except Exception as exc:
            result["skip_reason"] = f"Wayback CDX request failed: {exc}"
            return result

        result["queried"] = True
        if resp.status_code != 200:
            result["skip_reason"] = f"Wayback CDX returned HTTP {resp.status_code}"
            return result

        try:
            rows = json.loads(resp.text)
        except json.JSONDecodeError:
            result["skip_reason"] = "Wayback CDX response was not valid JSON"
            return result

        # First row is the header (["original"]) when results exist.
        if len(rows) <= 1:
            return result

        seen: set[str] = set()
        for row in rows[1:]:
            if row and row[0]:
                seen.add(row[0])
        result["urls"] = sorted(seen)[:limit]
        return result
    finally:
        if own_client:
            await client.aclose()
