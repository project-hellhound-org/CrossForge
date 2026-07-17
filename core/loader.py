"""
CrossForge SSRF Agent — Candidate Loader
==========================================
v5.1: uses the rebuilt spider_adapter with smart filtering and auth detection.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path

from core.models import Candidate, ParamLocation
from core.spider_adapter import detect_spider_format, adapt
from core.console import ok, warn, info, dim, tprint, color, C

logger = logging.getLogger("crossforge.loader")
REQUIRED_KEYS   = ("url", "parameter")
VALID_LOCATIONS = {loc.value for loc in ParamLocation}


class CandidateLoadError(ValueError):
    pass


class LoadResult:
    def __init__(self, candidates, leaked_credentials, base_url=None):
        self.candidates         = candidates
        self.leaked_credentials = leaked_credentials
        self.base_url           = base_url


def load_candidates(path):
    raw_path = Path(path)
    try:
        text = raw_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise CandidateLoadError(f"Cannot read '{raw_path}': {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CandidateLoadError(f"Invalid JSON in '{raw_path}': {exc}") from exc

    if detect_spider_format(data):
        return load_from_spider_dict(data, source_label=str(raw_path))
    if isinstance(data, list):
        cands = _load_flat_array(data, raw_path)
        return LoadResult(candidates=cands, leaked_credentials=[], base_url=_infer_base_url(cands))
    raise CandidateLoadError(f"'{raw_path}': unrecognised format.")


def load_from_spider_dict(data: dict, source_label: str) -> "LoadResult":
    """
    Shared entry point for anything that produces a Spider-format dict:
    an externally-supplied --input file (via load_candidates() above) OR
    core.crawler.NativeCrawler's own recon output. Both get IDENTICAL
    treatment from here on — same triage, same prescore filtering, same
    auth/leak/method-correction reporting. `source_label` is only used in
    messages (e.g. the file path, or the crawled target URL) — it doesn't
    need to be a real file.
    """
    tool   = data.get("meta", {}).get("tool", "Hellhound Spider")
    target = data.get("meta", {}).get("target", "unknown")
    total  = len(data.get("endpoints", []))
    info(f"Spider format: {color(tool, C.BWHITE)} → {color(target, C.BCYAN)} ({color(str(total), C.BWHITE)} endpoints)")

    result = adapt(data)

    if result.auth_required_urls:
        tprint()
        warn(f"{len(result.auth_required_urls)} endpoint(s) require auth (all 302 redirects):")
        for u in result.auth_required_urls[:5]:
            tprint(f"   {color(u, C.DIM)}")
        if len(result.auth_required_urls) > 5:
            tprint(f"   {color(f'...and {len(result.auth_required_urls)-5} more', C.DIM)}")
        warn("Use --bearer TOKEN or --cookie NAME=VALUE to scan authenticated endpoints.")
        tprint()

    if result.leaked_credentials:
        tprint()
        warn("CREDENTIAL LEAK in Spider response headers:")
        for lc in result.leaked_credentials:
            tprint(f"   {color(lc['header'], C.BYELLOW)}: {color(str(lc['value'])[:80], C.DIM)}")
        tprint()

    if result.method_corrected_urls:
        dim(f"GET→POST corrected on {len(result.method_corrected_urls)} endpoint(s) (HTTP 405 observed)")
    if result.skipped_urls:
        dim(f"Skipped {len(result.skipped_urls)} endpoint(s): no SSRF-sink signal")

    # [Phase 1 rebuild bugfix] Previously: `filtered = total_before_filter -
    # total_after_filter`, silently diffing across an additive HOST_HEADER
    # synthesis stage that happens *between* those two counts — when
    # synthesis added more than filtering removed, this went negative
    # (e.g. "Filtered -11 zero-score candidate(s)" alongside "37 raw → 48
    # after filter", which is real net growth, not a bug in the arithmetic
    # itself, just in what was being subtracted from what). Each stage is
    # now reported as what it actually is.
    if result.zero_score_dropped:
        dim(f"Filtered {result.zero_score_dropped} zero-score candidate(s) (no SSRF-relevance signal)")
    if result.host_header_added:
        dim(f"Added {result.host_header_added} Host-header candidate(s) for HIGH-tier endpoint(s)")
    if result.dedup_dropped:
        dim(f"Deduplicated {result.dedup_dropped} candidate(s) (identical url+method+param+location)")

    if not result.candidates:
        raise CandidateLoadError(f"'{source_label}' produced 0 usable candidates after filtering.")

    ok(f"Queued {color(str(len(result.candidates)), C.BWHITE, C.BOLD)} candidate(s) "
       f"(expanded from {result.total_before_filter} raw parameter-candidate(s) "
       f"→ {result.total_after_filter} final, after zero-score filtering, "
       f"Host-header synthesis, and dedup)")

    # Vuln-type breakdown — tells the operator immediately what SSRF surface
    # was found without waiting for the full scan summary.
    from collections import Counter
    from core.models import VulnType
    type_counts = Counter(
        c.vuln_type.value for c in result.candidates
        if c.vuln_type != VulnType.UNKNOWN
    )
    if type_counts:
        breakdown = ", ".join(f"{k}:{v}" for k, v in type_counts.most_common(6))
        info(f"SSRF surface types: {color(breakdown, C.BBLUE)}")

    return LoadResult(
        candidates=result.candidates,
        leaked_credentials=result.leaked_credentials,
        base_url=_infer_base_url(result.candidates),
    )


def _load_flat_array(data, path):
    candidates = []
    for i, entry in enumerate(data, 1):
        if not isinstance(entry, dict):
            raise CandidateLoadError(f"Entry {i}: expected object, got {type(entry).__name__}")
        missing = [k for k in REQUIRED_KEYS if k not in entry]
        if missing:
            raise CandidateLoadError(f"Entry {i}: missing key(s) {missing}")
        location = entry.get("location", "query")
        if location not in VALID_LOCATIONS:
            raise CandidateLoadError(f"Entry {i}: invalid location '{location}'. Must be one of {sorted(VALID_LOCATIONS)}.")
        candidates.append(Candidate(
            target_url=entry["url"],
            method=entry.get("method", "GET").upper(),
            parameter=entry["parameter"],
            param_location=ParamLocation(location),
            original_value=entry.get("value", ""),
            headers=entry.get("headers", {}) or {},
            cookies=entry.get("cookies", {}) or {},
            body_template=entry.get("body_template"),
        ))
    ok(f"Loaded {color(str(len(candidates)), C.BWHITE, C.BOLD)} candidate(s) from flat array")
    return candidates


def _infer_base_url(candidates):
    if not candidates:
        return None
    try:
        import httpx
        u = httpx.URL(candidates[0].target_url)
        return f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")
    except Exception:
        return None
