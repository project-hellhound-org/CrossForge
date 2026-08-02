"""
HELLHOUND SSRF v5.0 - Phase 1 Extension: Predictable Path Discovery
====================================================================
Wordlist-based probe that discovers SSRF-prone endpoints not found by the
Spider or spec-based (OpenAPI/GraphQL) adapters.

WHY THIS EXISTS
---------------
The Spider finds pages it can browse and crawl. OpenAPI/GraphQL adapters find
spec-documented endpoints. Neither discovers endpoints that are:
  - Unlisted in specs but present on the server (/admin/fetch, /api/proxy ...)
  - Hidden behind standard paths that every app framework includes by default
  - Predictable from common naming conventions used across SaaS platforms

This probe takes the target base URL, probes a curated wordlist of SSRF-prone
paths, and converts confirmed-reachable paths into Candidate objects that feed
into the same Phase 0 pre-scoring pipeline as Spider-discovered candidates.

Requested by: ABIN4V, team review July 2026:
    "And also make the agent to check the inputs and paths provided by the
     spider to use Predictable paths and vuln possibility using Word-Lists
     (Phase 1 Recon)"

Integration
-----------
Called from agent.py after Spider loading and OpenAPI/GraphQL discovery:

    from core.path_probe import probe_predictable_paths
    pp_cands = await probe_predictable_paths(base_url, auth_headers, cfg)
    candidates.extend(pp_cands)

The candidates returned are structurally identical to Spider-sourced candidates
and flow through Phases 0-10 without any special handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

import httpx

from core.models import (
    Candidate,
    ParamLocation,
)

logger = logging.getLogger(__name__)

# Built-in wordlist — 75 SSRF-prone predictable paths across 10 categories
_WORDLIST_PATH = Path(__file__).parent / "payloads" / "ssrf_paths.json"

# HTTP status codes that confirm a path exists on the server.
# We include 400/401/403/405 because a server returning these is still
# actively handling the request — the path is real. 404 means absent.
_PRESENT_CODES: frozenset[int] = frozenset({
    200, 201, 204,       # success responses
    301, 302, 307, 308,  # redirect (path exists, server routes it somewhere)
    400,                 # bad request (path exists but our probe body is wrong)
    401, 403,            # auth-required / forbidden (path exists, protected)
    405,                 # method not allowed (path exists, try other method)
    415,                 # unsupported media type (path exists, wrong content-type)
})

# Map HTTP method -> ParamLocation for generated Candidates
_METHOD_LOCATION: dict[str, ParamLocation] = {
    "GET":    ParamLocation.QUERY,
    "POST":   ParamLocation.BODY_JSON,
    "PUT":    ParamLocation.BODY_JSON,
    "PATCH":  ParamLocation.BODY_JSON,
    "DELETE": ParamLocation.QUERY,
}


def _load_wordlist(custom_path: str = "") -> list[dict]:
    """Load the built-in wordlist, optionally overriding with a custom file.

    Args:
        custom_path: If non-empty, load from this path instead of the built-in.

    Returns:
        List of wordlist entry dicts. Empty list on any error.
    """
    path = Path(custom_path) if custom_path else _WORDLIST_PATH
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning("[PathProbe] Wordlist not found: %s", path)
        return []
    except json.JSONDecodeError as exc:
        logger.warning("[PathProbe] Wordlist JSON parse error in %s: %s", path, exc)
        return []
    except Exception as exc:
        logger.warning("[PathProbe] Failed to load wordlist %s: %s", path, exc)
        return []


async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    entry: dict,
    timeout: float,
) -> list[Candidate]:
    """Probe one wordlist entry and return Candidates if the path is reachable.

    Strategy:
    1. Send HEAD request (no body, minimal bandwidth).
    2. If HEAD is rejected (405) or fails, fall back to GET.
    3. If the response status is in _PRESENT_CODES, generate one Candidate
       per SSRF-prone parameter listed in the wordlist entry.

    Args:
        client   : Shared httpx.AsyncClient for this probe batch.
        base_url : Target root URL, e.g. "http://target.com"
        entry    : Single wordlist dict with keys: path, method, params, note, category.
        timeout  : Per-request timeout in seconds.

    Returns:
        List of Candidate objects (one per parameter). Empty if path is absent.
    """
    path     = entry.get("path", "")
    params   = entry.get("params") or ["url"]
    method   = entry.get("method", "GET").upper()
    note     = entry.get("note", "")
    category = entry.get("category", "url_fetch")

    target_url = base_url.rstrip("/") + path
    status: Optional[int] = None

    # --- Step 1: HEAD probe ---
    try:
        resp = await client.head(target_url, timeout=timeout)
        status = resp.status_code
    except (httpx.TimeoutException, httpx.ConnectError):
        # Server unreachable for this path — skip silently
        return []
    except httpx.HTTPError:
        # HEAD failed at the HTTP level — fall through to GET
        pass

    # --- Step 2: GET fallback (405 = method not allowed for HEAD) ---
    if status is None or status == 405:
        try:
            resp = await client.get(target_url, timeout=timeout)
            status = resp.status_code
        except (httpx.TimeoutException, httpx.ConnectError):
            return []
        except httpx.HTTPError:
            return []

    # Path absent — not worth probing
    if status not in _PRESENT_CODES:
        return []

    # --- Path confirmed reachable --- generate one Candidate per SSRF parameter ---
    param_location = _METHOD_LOCATION.get(method, ParamLocation.QUERY)
    candidates: list[Candidate] = []

    context_note = f"[PathProbe] path={path} HTTP={status} category={category}"
    if note:
        context_note += f" -- {note}"

    for param in params:
        c = Candidate(
            target_url     = target_url,
            method         = method,
            parameter      = param,
            param_location = param_location,
            original_value = "",
        )
        # Encode discovery context into pre_score_reasons so it appears in reports
        c.pre_score_reasons.append(context_note)
        candidates.append(c)

    logger.info(
        "[PathProbe] %s %s -> HTTP %d | +%d candidate(s) %s",
        method, target_url, status, len(candidates),
        str(params),
    )
    return candidates


async def probe_predictable_paths(
    base_url: str,
    auth_headers: dict,
    cfg: dict,
    proxy: Optional[str] = None,
) -> list[Candidate]:
    """Main entry point: probe full wordlist against base_url, return Candidates.

    Called from agent.py after Spider loading and OpenAPI/GraphQL discovery.
    Respects the [path_probe] config block:

        path_probe:
          enabled: true
          concurrency: 10
          timeout: 5.0
          max_candidates: 300
          wordlist: ""          # empty = use built-in ssrf_paths.json

    Args:
        base_url     : Target root URL ("http://target.com")
        auth_headers : Auth headers from auth_manager (bearer, cookies, etc.)
        cfg          : Full loaded config dict
        proxy        : Optional HTTP proxy string for httpx

    Returns:
        De-duplicated list of Candidate objects, capped at max_candidates.
    """
    probe_cfg   = cfg.get("path_probe", {})
    if not probe_cfg.get("enabled", True):
        logger.debug("[PathProbe] Disabled in config — skipping")
        return []

    timeout     = float(probe_cfg.get("timeout", 5.0))
    concurrency = int(probe_cfg.get("concurrency", 10))
    max_cands   = int(probe_cfg.get("max_candidates", 300))
    custom_wl   = probe_cfg.get("wordlist", "")

    wordlist = _load_wordlist(custom_wl)
    if not wordlist:
        logger.warning("[PathProbe] Empty wordlist — no predictable-path candidates generated")
        return []

    logger.info(
        "[PathProbe] Starting: base=%s entries=%d concurrency=%d timeout=%.1fs",
        base_url, len(wordlist), concurrency, timeout,
    )

    # Shared HTTP client headers (auth + user-agent)
    client_headers: dict = {
        "User-Agent": "CrossForge-PathProbe/1.0",
        **auth_headers,
    }
    transport_kwargs: dict = {"verify": False}
    if proxy:
        transport_kwargs["proxy"] = proxy

    all_candidates: list[Candidate] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def _worker(entry: dict) -> None:
        async with semaphore:
            try:
                async with httpx.AsyncClient(
                    headers        = client_headers,
                    follow_redirects = False,  # raw status matters more than final URL
                    **transport_kwargs,
                ) as client:
                    found = await _probe_path(client, base_url, entry, timeout)
                    all_candidates.extend(found)
            except Exception as exc:
                logger.debug(
                    "[PathProbe] Unhandled exception on path %s: %s",
                    entry.get("path", "?"), exc,
                )

    await asyncio.gather(*[asyncio.create_task(_worker(e)) for e in wordlist])

    # De-duplicate: same (url, param, method) can appear in overlapping wordlist entries
    seen: set[tuple] = set()
    unique: list[Candidate] = []
    for c in all_candidates:
        key = (c.target_url, c.parameter, c.method)
        if key not in seen:
            seen.add(key)
            unique.append(c)

    # Cap to prevent queue explosion on very large custom wordlists
    result = unique[:max_cands]
    logger.info(
        "[PathProbe] Complete: %d raw hits -> %d unique candidates (cap=%d)",
        len(all_candidates), len(result), max_cands,
    )
    return result
