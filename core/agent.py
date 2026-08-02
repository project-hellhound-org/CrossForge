"""
CrossForge SSRF Agent — Core Orchestrator
==========================================
10-phase pipeline with per-phase clear console output.
Fixes all issues seen in the Juice Shop run:

  - Phase-by-phase output (not a single spinning HUD)
  - Auth-redirect detection and operator warning
  - Candidate quality filter before Phase 1 baseline
  - URL displayed without truncation (right-truncate path only)
  - Phase 6 gate requires SSRF-specific error (P0 fix)
  - composite_z cap + 2-dim noise floor (P1 fix)
"""

from __future__ import annotations
import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from core.models import (
    ScanMode, ScanReport, ConfidenceTier, EvidenceArtifact, Candidate, Finding,
)
from core.console import (
    C, color, phase_header, phase_result, section,
    ok, warn, err, info, dim, skip, vprint, found,
    print_finding_card, print_auth_warning, StatusBoard, tprint,
    progress_bar, lifecycle_header, lifecycle_result,
)
from core.http_client    import HttpClient, RateLimiter
from core.loader         import load_candidates, load_from_spider_dict
from core.crawler        import CrawlConfig, run_crawl
from core.prescore       import score_candidate, triage_queue
from core.baseline       import establish_baseline, InfraNoiseTracker
from core.context_classifier import classify_context
from core.waf_detector   import fingerprint_waf
from core.differential   import (
    probe_candidate, is_suspicious, describe_signature,
    SUSPICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD_WAF,
)
from core.oob_hub        import OOBHub
from core.authorized_action_gate import AuthorizedActionGate, reconstruct_candidate  # [GATE]
from core.file_upload_probe import probe_upload_endpoints
from core.chaining       import detect_dns_rebinding
from core import scoring, feedback, reporter
from core.auth_manager   import AuthManager
from core.known_exploits import get_registry

logger = logging.getLogger("crossforge.agent")

_DEFAULT_CONFIG = Path(__file__).parent / "config.yaml"

# Internal IP / loopback regex for Phase 6 gate
_INTERNAL_RE = re.compile(
    r"127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"169\.254\.|::1|localhost",
    re.I,
)

# Redirect-to-login pattern
_LOGIN_REDIRECT_RE = re.compile(
    r"/(login|signin|auth|session|oauth|sso)\b", re.I
)


class CrossForgeAgent:

    def __init__(self, config_path: "str | Path" = _DEFAULT_CONFIG):
        with open(config_path) as f:
            self.cfg = yaml.safe_load(f)

        self.scan_mode = ScanMode(self.cfg.get("scan_mode", "detect"))

        rate_cfg     = self.cfg.get("rate_limit", {})
        self._limiter  = RateLimiter(
            requests_per_second=rate_cfg.get("requests_per_second", 20),
            burst=rate_cfg.get("burst", 40),
        )
        http_cfg     = self.cfg.get("http", {})
        self._proxy  = http_cfg.get("proxy")     # reused by the native crawler, see run()
        self._client   = HttpClient(
            rate_limiter=self._limiter,
            timeout=http_cfg.get("timeout", 10.0),
            proxy=http_cfg.get("proxy"),
            follow_redirects=http_cfg.get("follow_redirects", True),
            max_redirects=http_cfg.get("max_redirects", 5),
        )
        self._gate = AuthorizedActionGate(self._client)  # [GATE] see core/authorized_action_gate.py

        oob_cfg     = self.cfg.get("oob", {})
        server_url  = oob_cfg.get("server_url")
        self._oob   = (
            OOBHub(server_url, oob_cfg.get("poll_interval", 5.0))
            if server_url else None
        )

        self._output_dir = Path(self.cfg.get("output", {}).get("dir", "reports"))
        self._output_dir.mkdir(exist_ok=True)
        self._max_hops   = self.cfg.get("chaining", {}).get("max_hops", 3)

        # Max candidates processed concurrently in the Phases 2–10 pipeline.
        # Raising this overlaps OOB sleep cycles and cuts wall-clock scan time
        # proportionally. Bounded by the rate_limit above, so it won't bypass
        # the per-second request budget regardless of this value.
        scan_cfg = self.cfg.get("scan", {})
        self._concurrency = int(scan_cfg.get("concurrency", 10))

        # Load known-exploit registry once
        get_registry()

        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        candidates_path: "str | Path | None" = None,
        target_url: "str | None" = None,
    ) -> ScanReport:
        t_start  = time.monotonic()
        report   = ScanReport()
        status   = StatusBoard(enabled=True)

        if not candidates_path and not target_url:
            err("No --input spider file and no target URL supplied — nothing to scan.")
            report.status     = "error"
            report.gap_reason = "no input"
            return report

        # ════════════════════════════════════════════════════════════════
        # RECON — NATIVE CRAWL (only when no --input spider file was given)
        # ════════════════════════════════════════════════════════════════
        # WHY: CrossForge previously *required* an externally-produced
        # Spider JSON file. If the operator only has a target URL, there
        # was no path to a scan at all. When candidates_path is absent,
        # we crawl the target ourselves and feed the result through the
        # EXACT SAME load_from_spider_dict() → spider_adapter.adapt() →
        # prescore.score_candidate() pipeline an externally-supplied
        # spider file goes through — see core/crawler.py's module
        # docstring for the full design rationale. If --input WAS given,
        # this block is skipped entirely and target_url (if also given)
        # is only used as a base_url fallback below.
        crawled_spider_data = None
        if not candidates_path:
            auth_cfg = self.cfg.get("auth", {}) or {}
            crawl_headers: dict = {}
            if auth_cfg.get("bearer_token"):
                crawl_headers["Authorization"] = f"Bearer {auth_cfg['bearer_token']}"
            elif auth_cfg.get("api_key"):
                crawl_headers[auth_cfg.get("api_key_header", "X-Api-Key")] = auth_cfg["api_key"]
            if auth_cfg.get("cookies"):
                crawl_headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in auth_cfg["cookies"].items()
                )

            crawl_cfg = CrawlConfig.from_dict(self.cfg.get("crawl", {}))
            try:
                crawled_spider_data = await run_crawl(
                    target_url,
                    crawl_cfg,
                    rate_limiter=self._limiter,   # same request budget as every other phase
                    proxy=self._proxy,
                    extra_headers=crawl_headers,
                )
            except Exception as exc:
                err(f"Native crawl failed: {exc}")
                report.status     = "error"
                report.gap_reason = f"crawl failed: {exc}"
                return report

        # ════════════════════════════════════════════════════════════════
        # LOAD
        # ════════════════════════════════════════════════════════════════
        # ════════════════════════════════════════════════════════════════
        # STAGE 1 — RECONNAISSANCE
        # ════════════════════════════════════════════════════════════════
        lifecycle_header(1)
        section("LOADING INPUT")
        try:
            if crawled_spider_data is not None:
                load_result = load_from_spider_dict(crawled_spider_data, source_label=target_url)
            else:
                load_result = load_candidates(candidates_path)
            candidates    = load_result.candidates
            leaked_creds  = load_result.leaked_credentials
            base_url      = load_result.base_url or target_url
        except Exception as exc:
            err(f"Failed to load candidates: {exc}")
            report.status    = "error"
            report.gap_reason = str(exc)
            return report

        source_label = candidates_path if candidates_path else f"native crawl of {target_url}"
        info(f"Loaded {color(str(len(candidates)), C.BWHITE, C.BOLD)} candidates from {color(str(source_label), C.DIM)}")

        if leaked_creds:
            tprint()
            warn(f"CREDENTIAL LEAK IN SPIDER HEADERS ({len(leaked_creds)} item(s)):")
            for lc in leaked_creds:
                tprint(f"   {color(lc['header'], C.BYELLOW)}: {color(str(lc['value'])[:60], C.DIM)}")
            tprint()

        # ════════════════════════════════════════════════════════════════
        # AUTH MANAGER
        # ════════════════════════════════════════════════════════════════
        auth_mgr = AuthManager.from_config(self.cfg, leaked_creds)
        if auth_mgr.has_auth:
            ok(f"Auth context ready — injecting into all candidates")

        # ════════════════════════════════════════════════════════════════
        # OPENAPI DISCOVERY
        # ════════════════════════════════════════════════════════════════
        openapi_count = 0
        auth_headers: dict = {}
        if auth_mgr.has_auth and candidates:
            _dummy = type("D", (), {"headers": {}, "cookies": {}, "param_location": candidates[0].param_location})()
            auth_mgr.inject(_dummy)
            auth_headers = _dummy.headers
        if base_url and self.cfg.get("openapi", {}).get("enabled", True):
            try:
                from core.openapi_adapter import discover_from_spec
                oa_cands = await discover_from_spec(base_url, auth_headers)
                if oa_cands:
                    from core import vuln_classifier as _vc
                    _vc.annotate_batch(oa_cands)
                    info(f"OpenAPI spec: +{color(str(len(oa_cands)), C.BBLUE, C.BOLD)} spec-derived candidate(s)")
                    candidates.extend(oa_cands)
                    openapi_count = len(oa_cands)
            except Exception as exc:
                dim(f"OpenAPI discovery skipped: {exc}")

        # ════════════════════════════════════════════════════════════════
        # GRAPHQL DISCOVERY  [Phase 1 rebuild]
        # ════════════════════════════════════════════════════════════════
        # Same shape as the OpenAPI block above by design — see
        # core/graphql_adapter.py's module docstring for why this is a
        # standalone, additive discovery pass rather than something wired
        # into core/crawler.py itself.
        graphql_count = 0
        if base_url and self.cfg.get("graphql", {}).get("enabled", True):
            try:
                from core.graphql_adapter import discover_from_graphql
                gq_timeout = self.cfg.get("graphql", {}).get("timeout", 8.0)
                gq_cands = await discover_from_graphql(base_url, auth_headers, timeout=gq_timeout)
                if gq_cands:
                    from core import vuln_classifier as _vc
                    _vc.annotate_batch(gq_cands)
                    info(f"GraphQL schema: +{color(str(len(gq_cands)), C.BBLUE, C.BOLD)} introspection-derived candidate(s)")
                    candidates.extend(gq_cands)
                    graphql_count = len(gq_cands)
            except Exception as exc:
                dim(f"GraphQL discovery skipped: {exc}")

        # PATH PROBE  [ABIN4V requirement — Phase 1 Recon]
        # ════════════════════════════════════════════════════════════════
        # Probes a curated wordlist of predictable SSRF-prone paths against
        # the target base URL. Finds endpoints the Spider never visited and
        # that are not documented in any OpenAPI/GraphQL spec — e.g.
        # /api/preview, /webhook/verify, /connectors/cloud-metadata.
        # These are common in real SaaS applications and are high-value
        # SSRF targets. See core/path_probe.py for full design rationale.
        path_probe_count = 0
        if base_url:
            try:
                from core.path_probe import probe_predictable_paths
                pp_cands = await probe_predictable_paths(
                    base_url,
                    auth_headers,
                    self.cfg,
                    proxy=self.cfg.get("http", {}).get("proxy"),
                )
                if pp_cands:
                    from core import vuln_classifier as _vc
                    _vc.annotate_batch(pp_cands)
                    info(
                        f"Path probe: +{color(str(len(pp_cands)), C.BGREEN, C.BOLD)}"
                        f" predictable-path candidate(s)"
                    )
                    candidates.extend(pp_cands)
                    path_probe_count = len(pp_cands)
            except Exception as exc:
                dim(f"Path probe skipped: {exc}")

        # FILE UPLOAD SSRF PROBE
        # ════════════════════════════════════════════════════════════════
        # Submits malicious SVG / DOCX / XML files to upload-accepting
        # endpoints and detects in-band SSRF signals (HTTP 500, metadata
        # keywords in response, response-time anomaly).
        upload_hit_count = 0
        if base_url and self.cfg.get("file_upload_probe", {}).get("enabled", True):
            try:
                _ssrf_url  = "http://169.254.169.254/latest/meta-data/"
                _oob_dom   = self._oob.collaborator_host() if self._oob else None
                upload_hits = await probe_upload_endpoints(
                    candidates, self._client,
                    ssrf_url=_ssrf_url,
                    oob_domain=_oob_dom,
                )
                upload_hit_count = len(upload_hits)
                for hit in upload_hits:
                    info(
                        f"Upload-SSRF: {hit['endpoint']} "
                        f"param={hit['parameter']} [{hit['file_type']}] — {hit['anomaly']}"
                    )
                if upload_hit_count:
                    ok(f"File-upload probe flagged {upload_hit_count} suspicious endpoint(s)")
            except Exception as exc:
                dim(f"File-upload probe skipped: {exc}")

        recon_rows = [
            ("Source",              color("Native crawl" if crawled_spider_data is not None else "Supplied spider file", C.BWHITE)),
            ("Endpoints/candidates", color(str(len(candidates)), C.BWHITE, C.BOLD)),
            ("OpenAPI-derived",      color(str(openapi_count), C.BBLUE if openapi_count else C.DIM)),
            ("GraphQL-derived",      color(str(graphql_count), C.BBLUE if graphql_count else C.DIM)),
            ("Path-probe hits",      color(str(path_probe_count), C.BGREEN if path_probe_count else C.DIM)),
            ("File-upload hits",     color(str(upload_hit_count), C.BYELLOW if upload_hit_count else C.DIM)),
            ("Credential leaks",     color(str(len(leaked_creds)), C.BYELLOW if leaked_creds else C.DIM)),
        ]
        if crawled_spider_data is not None:
            cs = crawled_spider_data["meta"]["crawl_stats"]
            recon_rows.insert(1, ("Pages crawled", color(str(cs["pages_fetched"]), C.BWHITE)))
            recon_rows.insert(2, ("Forms found",    color(str(cs["forms_found"]), C.BWHITE)))
            recon_rows.insert(3, ("JS files analyzed", color(str(cs["js_files_analyzed"]), C.BWHITE)))
            # [Phase 1 rebuild] quality-gate + recon-intel visibility
            qg = cs.get("quality_gate")
            if qg and sum(qg.values()):
                recon_rows.insert(4, ("Junk pages filtered", color(str(sum(qg.values())), C.DIM)))
            ri = crawled_spider_data.get("recon_intel", {})
            sub = ri.get("subdomains")
            if sub and sub.get("subdomains"):
                recon_rows.append(("Subdomains found", color(str(len(sub["subdomains"])), C.BBLUE)))
        lifecycle_result(1, recon_rows)


        # ════════════════════════════════════════════════════════════════
        # STAGE 2 — SCANNING
        # ════════════════════════════════════════════════════════════════
        lifecycle_header(2)

        # ════════════════════════════════════════════════════════════════
        # PHASE 0: PRE-SCORING
        # ════════════════════════════════════════════════════════════════
        phase_header(0, extra=f"{len(candidates)} candidates")
        status.start()
        status.update(phase="phase-0", detail="scoring", total=len(candidates))

        for c in candidates:
            score_candidate(c)
        candidates = triage_queue(candidates)

        high   = sum(1 for c in candidates if c.pre_score_tier.value == "high")
        medium = sum(1 for c in candidates if c.pre_score_tier.value == "medium")
        low    = sum(1 for c in candidates if c.pre_score_tier.value == "low")

        phase_result(0, [
            ("Total candidates queued",     color(str(len(candidates)), C.BWHITE, C.BOLD)),
            ("HIGH tier  (full scan)",      color(str(high),   C.BRED,     C.BOLD)),
            ("MEDIUM tier (subset scan)",   color(str(medium), C.BYELLOW,  C.BOLD)),
            ("LOW tier (minimal probes)",   color(str(low),    C.DIM)),
            ("OpenAPI-sourced",             color(str(openapi_count), C.BBLUE) if openapi_count else color("0", C.DIM)),
            ("OOB server",                  color(self._oob.server_url if self._oob else "disabled", C.BCYAN if self._oob else C.DIM)),
        ])

        # ════════════════════════════════════════════════════════════════
        # PHASE 1: BASELINE COLLECTION
        # ════════════════════════════════════════════════════════════════
        phase_header(1, extra=f"5 samples per candidate")
        noise_tracker = InfraNoiseTracker(noise_threshold=3)
        auth_skipped  = 0
        baseline_ok   = 0
        baseline_fail = 0

        for i, cand in enumerate(candidates):
            status.update(
                phase="phase-1",
                detail=_short_label(cand),
                done=i, total=len(candidates),
            )
            status.inc_requests()

            if auth_mgr.has_auth:
                auth_mgr.inject(cand)

            try:
                bl = await establish_baseline(self._client, cand)
                if bl is None:
                    baseline_fail += 1
                    continue

                # [FIX-3] Detect auth redirect during baseline
                if bl.dominant_status == 302 and _is_login_redirect(bl):
                    if not auth_mgr.has_auth:
                        print_auth_warning(
                            cand.target_url,
                            bl.redirect_targets[0] if bl.redirect_targets else "unknown",
                        )
                        auth_skipped += 1
                    cand.baseline = None   # skip Phase 4 for this candidate
                    continue

                cand.baseline = bl
                noise_tracker.record(cand, bl)
                baseline_ok += 1
            except Exception as exc:
                logger.debug("Baseline failed %s: %s", cand.candidate_id[:8], exc)
                baseline_fail += 1

        flagged = noise_tracker.propagate_flags(candidates)
        phase_result(1, [
            ("Baseline established",    color(str(baseline_ok),   C.BGREEN, C.BOLD)),
            ("Auth-redirect skipped",   color(str(auth_skipped),  C.BYELLOW if auth_skipped else C.DIM)),
            ("Unreachable/failed",       color(str(baseline_fail), C.DIM)),
            ("Infra-noise flagged",      color(str(flagged),       C.BYELLOW if flagged else C.DIM)),
        ])

        if auth_skipped and not auth_mgr.has_auth:
            tprint()
            warn(f"{auth_skipped} endpoint(s) require authentication.")
            warn("Provide --bearer TOKEN, --api-key KEY, or --cookie NAME=VALUE to scan them.")
            tprint()

        lifecycle_result(2, [
            ("Candidates baselined",  color(str(baseline_ok), C.BGREEN, C.BOLD)),
            ("Auth-gated (skipped)",  color(str(auth_skipped), C.BYELLOW if auth_skipped else C.DIM)),
            ("Unreachable",           color(str(baseline_fail), C.DIM)),
            ("Infra-noise flagged",   color(str(flagged), C.BYELLOW if flagged else C.DIM)),
        ])
        dim("WAF fingerprinting runs per-candidate alongside detection — see Stage 3 for those results.")

        # Only process candidates with a valid baseline
        active = [c for c in candidates if c.baseline is not None]
        if not active:
            warn("No candidates have a usable baseline. Scan cannot continue.")
            report.status = "no_candidates"
            status.stop()
            return report

        # Start OOB polling
        if self._oob:
            await self._oob.start_polling()

        # ════════════════════════════════════════════════════════════════
        # PHASES 2–10: Per-candidate pipeline
        # ════════════════════════════════════════════════════════════════
        pivot_queue: list = []
        findings_count = {"tentative": 0, "firm": 0, "certain": 0, "critical_plus": 0}

        # Aggregate counters for the retrospective lifecycle-stage summaries
        # printed after this loop (see run()'s post-loop section below for
        # why these are retrospective rather than live per-phase banners).
        from collections import Counter
        self._enum_stats      = {"candidates_enumerated": 0, "context_classes": Counter()}
        self._scan_stats      = {"waf_detected": 0, "waf_vendors": Counter()}
        self._detect_stats    = {"anomalies_found": 0, "oob_interactions_confirmed": 0}
        self._exploit_stats   = {"evidence_artifacts": Counter(), "proposals_generated": 0}
        self._postexploit_stats = {"chains_built": 0, "pivot_targets_found": 0, "dns_rebinds_detected": 0}

        # Run all candidates concurrently, bounded by self._concurrency.
        # Concurrency is controlled by spawning exactly self._concurrency
        # worker tasks — each task loops on active.pop(0) until the shared
        # queue is empty. OOB sleep cycles (Phase 5) from different
        # candidates overlap instead of stacking sequentially, cutting
        # wall-clock scan time proportionally.
        # NOTE: active.pop(0) is safe under asyncio's cooperative scheduler:
        # no two coroutines can interleave within a synchronous statement, so
        # the pop() and the subsequent triage_queue re-sort are both atomic
        # at the asyncio event-loop level — no OS-thread lock needed.
        # CONSTRAINT: atomicity holds only for a single-threaded event loop.
        # Do not parallelize workers across threads or processes without
        # revisiting all shared-state assumptions in this block.
        total_active = len(active)

        async def _worker() -> None:
            # `while active:` is a synchronous truthiness check; active.pop(0)
            # runs immediately after with no `await` between them, so the list
            # cannot become empty between the check and the pop — IndexError is
            # structurally unreachable under asyncio's cooperative scheduler.
            while active:
                cand = active.pop(0)

                status.update(
                    phase="scanning",
                    detail=_short_label(cand),
                    done=total_active - len(active), total=total_active,
                    findings=sum(findings_count.values()),
                )

                try:
                    await self._process_candidate(
                        cand, report, pivot_queue, findings_count, status,
                        remaining_candidates=active,
                    )
                except Exception as exc:  # noqa: BLE001
                    # Isolate per-candidate failures: a single network error,
                    # parse error, or unexpected exception must not cancel all
                    # other in-flight workers via asyncio.gather's default
                    # exception-propagation behaviour.  Log and continue.
                    self._log.warning(
                        "[worker] candidate %s raised %s: %s — skipping",
                        getattr(cand, 'candidate_id', '?'),
                        type(exc).__name__,
                        exc,
                        exc_info=True,   # include full stack trace for real bugs
                    )
                    # Record in the report so analysts know this candidate was
                    # never fully probed (unknown coverage, not "clean scan").
                    report.skipped_candidates.append({
                        "candidate_id": getattr(cand, 'candidate_id', '?'),
                        "url":          getattr(cand, 'url', '?'),
                        "parameter":    getattr(cand, 'parameter', '?'),
                        "error_type":   type(exc).__name__,
                        "error":        str(exc),
                    })

                status.inc_requests()

                # Re-sort remaining queue in-place to honor any Phase 10 tier bumps.
                if active:
                    active[:] = triage_queue(active)

        # Spawn N concurrent dynamic workers bounded by config concurrency.
        workers = [asyncio.create_task(_worker()) for _ in range(self._concurrency)]
        await asyncio.gather(*workers)

        # Process pivot candidates (chain hopping)
        hop = 0
        while pivot_queue and hop < self._max_hops:
            hop += 1
            next_batch: list = []
            for pivot in pivot_queue:
                pivot_cands = self._make_pivot_candidates(pivot)
                for pc in pivot_cands:
                    score_candidate(pc)
                    if auth_mgr.has_auth:
                        auth_mgr.inject(pc)
                    try:
                        pc.baseline = await establish_baseline(self._client, pc)
                    except Exception:
                        continue
                    if pc.baseline is None:
                        continue
                    await self._process_candidate(
                        pc, report, next_batch, findings_count, status
                    )
            pivot_queue = next_batch

        # ════════════════════════════════════════════════════════════════
        # STAGES 3–6 — retrospective summaries of the interleaved
        # per-candidate pipeline that just ran (see _process_candidate and
        # the _LIFECYCLE_META comment in core/console.py for why these are
        # reported after the fact rather than as live sequential banners).
        # ════════════════════════════════════════════════════════════════
        top_waf = self._scan_stats["waf_vendors"].most_common(3)
        lifecycle_header(3)
        lifecycle_result(3, [
            ("Candidates enumerated",  color(str(self._enum_stats["candidates_enumerated"]), C.BWHITE, C.BOLD)),
            ("Context classes seen",   color(", ".join(f"{k}:{v}" for k, v in self._enum_stats["context_classes"].most_common()) or "none", C.DIM)),
            ("WAF detected on",        color(str(self._scan_stats["waf_detected"]), C.BYELLOW if self._scan_stats["waf_detected"] else C.DIM)),
            ("Top WAF vendor(s)",      color(", ".join(f"{k}:{v}" for k, v in top_waf) or "none", C.DIM)),
        ])

        lifecycle_header(4)
        _oob_label = (
            color(str(self._detect_stats["oob_interactions_confirmed"]), C.BRED, C.BOLD)
            if self._detect_stats["oob_interactions_confirmed"]
            else (
                color("0", C.DIM)
                if self._oob
                else color("SKIPPED — no OOB server configured", C.DIM)
            )
        )
        lifecycle_result(4, [
            ("Anomalies found",             color(str(self._detect_stats["anomalies_found"]), C.BYELLOW if self._detect_stats["anomalies_found"] else C.DIM)),
            ("OOB interactions confirmed",  _oob_label),
        ])

        top_evidence = self._exploit_stats["evidence_artifacts"].most_common(5)
        lifecycle_header(5)
        if not self._oob and not sum(self._exploit_stats["evidence_artifacts"].values()):
            # Stage 5 only runs meaningful OOB-based exploitation when an OOB
            # server is configured.  Evidence collection (cloud-metadata checks)
            # still runs; show a clear SKIPPED row for the OOB sub-phase.
            lifecycle_result(5, [
                ("Evidence artifacts collected", color(str(sum(self._exploit_stats["evidence_artifacts"].values())), C.DIM)),
                ("OOB-based exploitation",        color("SKIPPED — no OOB server configured", C.DIM)),
                ("By type",                       color("none", C.DIM)),
            ])
        else:
            lifecycle_result(5, [
                ("Evidence artifacts collected", color(str(sum(self._exploit_stats["evidence_artifacts"].values())), C.BRED, C.BOLD) if self._exploit_stats["evidence_artifacts"] else color("0", C.DIM)),
                ("By type",                      color(", ".join(f"{k}:{v}" for k, v in top_evidence) or "none", C.DIM)),
            ])

        lifecycle_header(6)
        lifecycle_result(6, [
            ("Chains built",           color(str(self._postexploit_stats["chains_built"]), C.BMAGENTA if self._postexploit_stats["chains_built"] else C.DIM)),
            ("Pivot targets found",    color(str(self._postexploit_stats["pivot_targets_found"]), C.DIM)),
            ("DNS rebinds detected",   color(str(self._postexploit_stats["dns_rebinds_detected"]), C.BYELLOW if self._postexploit_stats["dns_rebinds_detected"] else C.DIM)),
        ])

        # ════════════════════════════════════════════════════════════════
        # DEDUPLICATION — collapse identical-signal cross-parameter dupes
        # ════════════════════════════════════════════════════════════════
        # See core/reporter.py::dedupe_findings for the full rationale.
        # Short version: prescore/spider_adapter expand one endpoint into
        # several guessed parameter-name candidates when the real sink
        # field is unknown; if 2+ of those guesses produce a byte-identical
        # differential signal, that's one endpoint-level observation, not
        # N independently-vulnerable parameters. OOB/evidence-confirmed
        # findings are untouched — only unconfirmed differential-anomaly
        # findings are eligible for collapse.
        dedup_stats = reporter.dedupe_findings(report)

        # findings_count was accumulated incrementally per-raw-finding
        # during the per-candidate loop above — recompute it fresh from
        # the (now deduped) report.findings so the summary reflects what
        # actually survived, not the pre-dedup raw count.
        findings_count = {"tentative": 0, "firm": 0, "certain": 0, "critical_plus": 0}
        for f in report.findings:
            key = getattr(f, "confidence_tier", "tentative").lower().replace("+", "_plus")
            findings_count[key] = findings_count.get(key, 0) + 1

        # ════════════════════════════════════════════════════════════════
        # FINAL DRAIN + REPORTS
        # ════════════════════════════════════════════════════════════════
        if self._oob:
            await asyncio.sleep(self._oob.poll_interval * 2)
            await self._oob.stop_polling()
            health = self._oob.get_health()
            if health["poll_error_count"]:
                report.errors.append(
                    f"OOB poll errors: {health['poll_error_count']}"
                )

        await self._client.close()
        status.stop()

        elapsed = time.monotonic() - t_start
        report.status = "complete"

        # [GATE] Sync the gate's operator-decision log into the report
        # before serialization. Stays empty unless run_authorized_evidence()
        # was actually called by an operator for this engagement.
        report.authorized_action_log = list(self._gate.log)

        json_path  = self._output_dir / "crossforge_report.json"
        sarif_path = self._output_dir / "crossforge_report.sarif"
        reporter.write_json_report(report, json_path)
        reporter.write_sarif_report(report, sarif_path)

        # ════════════════════════════════════════════════════════════════
        # FINAL SUMMARY
        # ════════════════════════════════════════════════════════════════
        # ════════════════════════════════════════════════════════════════
        # STAGE 7 — REPORTING
        # ════════════════════════════════════════════════════════════════
        lifecycle_header(7)
        phase_header(9, "SCAN COMPLETE", extra=f"{elapsed:.1f}s")
        skipped_count = len(report.skipped_candidates)
        scanned_count = total_active - skipped_count
        summary_rows = [
            ("Duration",            color(f"{elapsed:.1f}s", C.BWHITE)),
            ("Candidates scanned",  color(str(scanned_count), C.BWHITE)),
        ]
        if skipped_count:
            summary_rows.append((
                "Skipped (errors)",
                color(
                    f"{skipped_count} candidate(s) errored — "
                    f"coverage unknown (see log + report skipped_candidates)",
                    C.BYELLOW,
                ),
            ))
        if dedup_stats["groups_collapsed"]:
            summary_rows.append((
                "Duplicate findings merged",
                color(
                    f"{dedup_stats['findings_merged']} "
                    f"({dedup_stats['groups_collapsed']} group(s), "
                    f"{dedup_stats['demoted']} demoted)",
                    C.BYELLOW,
                ),
            ))
        summary_rows.extend([
            ("Findings — TENTATIVE",color(str(findings_count["tentative"]),   C.BCYAN)),
            ("Findings — FIRM",     color(str(findings_count["firm"]),        C.BYELLOW)),
            ("Findings — CERTAIN",  color(str(findings_count["certain"]),     C.BRED, C.BOLD)),
            ("Findings — CRITICAL+",color(str(findings_count["critical_plus"]),C.BRED, C.BOLD)),
        ])
        if report.pending_proposals:
            summary_rows.append((
                "Pending action proposals",
                color(
                    f"{len(report.pending_proposals)} finding(s) await operator review "
                    f"— see report.pending_proposals, none have been executed",
                    C.BYELLOW,
                ),
            ))
        summary_rows.extend([
            ("JSON report",         color(str(json_path),  C.DIM)),
            ("SARIF report",        color(str(sarif_path), C.DIM)),
        ])
        phase_result(9, summary_rows)

        return report

    # ------------------------------------------------------------------
    # Per-candidate pipeline (Phases 2–10)
    # ------------------------------------------------------------------

    async def _process_candidate(
        self,
        cand: Candidate,
        report: ScanReport,
        pivot_queue: list,
        findings_count: dict,
        status: StatusBoard,
        remaining_candidates: "list[Candidate] | None" = None,
    ) -> None:
        # Sibling pool for Phase 10 adaptive propagation.
        # Falls back to empty list when called from pivot processing paths
        # that don't yet have a meaningful sibling pool to pass.
        _siblings: list[Candidate] = remaining_candidates if remaining_candidates is not None else []
        cid = cand.candidate_id

        # Phase 2: Context
        status.update(phase="2-context", detail=_short_label(cand))
        classify_context(cand)
        self._enum_stats["candidates_enumerated"] += 1
        self._enum_stats["context_classes"][cand.context_class.value] += 1

        # Phase 3: WAF fingerprint
        status.update(phase="3-waf")
        await fingerprint_waf(self._client, cand)
        if cand.waf_vendor:
            self._scan_stats["waf_detected"] += 1
            self._scan_stats["waf_vendors"][cand.waf_vendor] += 1

        # Phase 4: Differential probe
        status.update(phase="4-probe")
        try:
            results = await probe_candidate(self._client, cand)
        except Exception as exc:
            logger.debug("Probe failed %s: %s", cid[:8], exc)
            return

        # [FIX C.3] Correlate Phase 3 (WAF fingerprint) with Phase 4
        # (differential probe): a WAF/bot-mitigation vendor in front of the
        # candidate adds its own response-shape noise on top of the origin
        # app's, so the same composite_z bar used for an unprotected target
        # over-fires here. Previously cand.waf_vendor was recorded but never
        # read again after Phase 3.
        effective_threshold = SUSPICIOUS_THRESHOLD_WAF if cand.waf_vendor else SUSPICIOUS_THRESHOLD
        suspicious = [r for r in results if is_suspicious(r, cand, threshold=effective_threshold)]
        if suspicious:
            self._detect_stats["anomalies_found"] += 1

        # Phase 5: OOB — runs unconditionally BEFORE the has_signal gate.
        # WHY: Blind SSRF produces no differential anomaly by design — the
        # server makes an outbound request but the HTTP response to the
        # scanner looks completely normal. Gating OOB behind a differential-
        # signal check (the previous behaviour) meant blind SSRF candidates
        # were dropped before the OOB payload was ever sent, breaking all
        # FIRM-tier confirmation. Fix: always issue the token, send the
        # payloads, wait for callbacks, THEN decide whether to continue.
        status.update(phase="5-oob")
        has_oob    = False
        async_pat  = False
        oob_token  = ""
        pivot_addrs: list[str] = []

        if self._oob:
            oob_token = self._oob.issue_token(cid)
            collab    = self._oob.collaborator_host()
            for entry in cand.payload_subset:
                if "{token}" in entry.get("payload", ""):
                    entry["payload"] = (
                        entry["payload"]
                        .replace("{token}", oob_token)
                        .replace("{collab_host}", collab)
                    )
                    try:
                        await self._client.send(
                            cand,
                            payload_value=entry["payload"],
                            payload_category=entry.get("category", "oob"),
                        )
                    except Exception:
                        pass

            # --- OOB efficiency fix -------------------------------------------
            # The background _poll_loop (oob_hub.py) already fetches from the
            # Interactsh server every poll_interval seconds and populates
            # self._oob.timeline in-place.  Per-candidate we only need to wait
            # long enough for at least ONE poll cycle to complete after our
            # payload was sent — not a FULL poll_interval per candidate.
            #
            # Strategy: check immediately (interaction may already be in
            # timeline if the server is fast), then poll in short 0.5 s
            # increments up to a maximum of poll_interval seconds total.
            # This keeps wall-clock per-candidate OOB overhead at ≤0.5 s
            # for fast interactions while still giving slow async targets
            # the full window.
            _oob_budget   = self._oob.poll_interval   # e.g. 5.0 s total budget
            _oob_tick     = 0.5                        # check every 0.5 s
            _oob_elapsed  = 0.0
            while _oob_elapsed < _oob_budget:
                if self._oob.has_interaction(cid):
                    break
                await asyncio.sleep(_oob_tick)
                _oob_elapsed += _oob_tick

            has_oob     = self._oob.has_interaction(cid)
            async_pat   = self._oob.is_async_pattern(cid)
            pivot_addrs = self._oob.internal_pivot_targets(cid)
            if has_oob:
                status.inc_findings()
                self._detect_stats["oob_interactions_confirmed"] += 1

        # URL reflection check: does the injected payload appear verbatim
        # in the response body? Servers that echo the URL in error messages
        # (e.g. "Could not fetch http://127.0.0.1/") expose server-side fetch
        # behaviour even when no statistical z-score anomaly is measured.
        # This is a distinct signal class from differential analysis.
        has_reflection = any(
            bool(r.payload) and bool(r.body_snippet) and r.payload in r.body_snippet
            for r in results
        )
        if has_reflection and not suspicious:
            # Reflection-only signal is weaker — log for traceability
            logger.debug(
                "[Phase 4] URL reflection detected on %s:%s — no z-score anomaly",
                cand.target_url, cand.parameter,
            )

        # Gate: evaluate all three signal paths together — AFTER OOB has
        # been sent and results have been collected.
        has_signal = bool(suspicious) or has_oob or has_reflection
        if not has_signal:
            return   # genuinely clean — no further phases

        # Phase 6: Evidence — GATED. Previously this block called
        # check_cloud_metadata / check_kubernetes_api / check_ecs_metadata /
        # check_oracle_cloud / build_port_state_map / fingerprint_internal_service /
        # check_file_read / check_crlf_injection / feedback.maybe_escalate_imdsv2
        # unconditionally whenever _warrants_evidence() returned True — see
        # core/authorized_action_gate.py's module docstring for the full
        # audit trail (including that config.yaml's evidence.aggressive
        # flag was dead code and never actually gated any of this).
        #
        # _warrants_evidence() itself makes no request — it's a pure
        # predicate over already-collected signals — so it's kept as
        # pre-gate triage. What changed is what a True result DOES: it now
        # produces a FindingProposal for operator review instead of
        # immediately firing every evidence method.
        status.update(phase="6-evidence")
        evidence: list[EvidenceArtifact] = []  # stays empty on the automatic path

        if self._warrants_evidence(suspicious, has_oob, cand):
            proposal = self._gate.propose(
                cand, suspicious, has_oob=has_oob, has_reflection=has_reflection,
                waf_vendor=cand.waf_vendor, oob_internal_addrs=pivot_addrs,
            )
            report.pending_proposals.append(proposal)
            self._exploit_stats["proposals_generated"] += 1
            status.inc_findings()

        # Phase 7: Chaining — pivot QUEUING removed from the automatic
        # path (was: extract_pivot_targets() result went straight into
        # pivot_queue, which the hop loop in run() then consumed
        # automatically up to self._max_hops deep, with no operator
        # checkpoint between hops).
        #
        # detect_dns_rebinding() is a pure comparison over IPs already
        # resolved during probing — safe to compute here, it's signal,
        # not an action. It's surfaced on the proposal's evidence_hint
        # rather than acted on.
        status.update(phase="7-chain")
        dns_rebind: list[str] = []
        for r in suspicious:
            if r.resolved_ip and cand.baseline and detect_dns_rebinding(
                cand.baseline.baseline_resolved_ip, r.resolved_ip
            ):
                dns_rebind.append(r.resolved_ip)
        self._postexploit_stats["dns_rebinds_detected"] += len(dns_rebind)

        # pivot_queue is no longer populated automatically. It stays as a
        # parameter here (and the hop loop in run() stays in place) purely
        # so operator-approved pivots — see run_authorized_evidence() and
        # AuthorizedActionGate.approve_pivots() — can reuse the same,
        # already-tested _make_pivot_candidates()/_process_candidate()
        # machinery instead of duplicating it.
        pivots: list = []
        chained = False

        # Phase 8: Scoring

        status.update(phase="8-scoring")
        open_ports: list[int] = []
        for art in evidence:
            open_ports.extend(art.extra.get("open_ports", []))
        registry      = get_registry()
        known_exploits = registry.lookup(open_ports) if open_ports else []

        tier = scoring.determine_tier(
            suspicious, has_oob, evidence, chained, cand, known_exploits
        )
        if tier is None:
            return

        # Phase 9: Build finding
        status.update(phase="9-report")
        if evidence and any(e.schema_matched for e in evidence):
            best_art   = next(e for e in evidence if e.schema_matched)
            chain_note = (
                f"Chained via {len(pivots)} pivot(s)." if chained else None
            )
            finding = reporter.build_evidence_finding(
                cand, best_art, tier, chain_note, known_exploits
            )
        elif chained:
            finding = reporter.build_chain_pivot_finding(
                cand, pivots,
                oob_token,
                self._oob.collaborator_host() if self._oob else None,
                known_exploits,
            )
        elif has_oob:
            finding = reporter.build_firm_finding(
                cand, suspicious[0], oob_token,
                self._oob.collaborator_host() if self._oob else "",
                async_pat,
            )
        else:
            finding = reporter.build_tentative_finding(cand, suspicious[0])

        # confidence_tier is a real declared field on Finding (see
        # core/models.py) — it serializes through asdict()/to_dict() into
        # JSON and SARIF like every other field.
        finding.confidence_tier = tier.value

        # [GATE] Tag with candidate_id so run_authorized_evidence() can find
        # and upgrade this exact finding later without matching on
        # url+parameter, which isn't guaranteed unique across candidates.
        finding.details["candidate_id"] = cid

        report.findings.append(finding)
        fidx = len(report.findings)

        tier_key = tier.value.lower().replace("+", "_plus")
        findings_count[tier_key] = findings_count.get(tier_key, 0) + 1
        status.inc_findings()

        # Print the finding card immediately
        print_finding_card(finding, idx=fidx)

        # Phase 10: Adaptive feedback
        status.update(phase="10-feedback")
        if tier in (ConfidenceTier.CERTAIN, ConfidenceTier.CRITICAL_PLUS):
            print(f"[Phase 10] Propagating feedback for confirmed finding on {cand.parameter}...")
            feedback.propagate_pattern(cand, _siblings)
            feedback.propagate_cloud_container_pattern(evidence, _siblings)
            if known_exploits:
                from urllib.parse import urlparse
                tgt_host = urlparse(cand.target_url).hostname or ""
                feedback.propagate_known_exploits(evidence, _siblings, tgt_host)
            print("[Phase 10] Feedback propagation complete.")

        if self._oob:
            h = self._oob.get_health()
            status.update(
                findings=sum(findings_count.values()),
            )

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # [GATE] Operator-invoked evidence execution
    # ------------------------------------------------------------------
    # NEVER called from run()'s automatic pipeline. This is the only path
    # by which report.pending_proposals can move past AWAITING_REVIEW.
    # Call it explicitly, after run() returns, once an operator has looked
    # at a proposal in report.pending_proposals and decided what to do.

    async def run_authorized_evidence(
        self, report: ScanReport, proposal_id: str, *,
        approved_methods: list[str], operator: str,
    ) -> Finding:
        """
        Executes operator-approved evidence methods against the candidate
        a pending proposal refers to, then upgrades that candidate's
        existing finding in place (built at TENTATIVE/FIRM tier during the
        automatic pass — see _process_candidate) using the same
        scoring.score()/determine_tier() logic the automatic pipeline
        uses, so CERTAIN/CRITICAL+ tiers stay reachable only through this
        explicit, named call.

        Uses proposal.candidate_snapshot (not an in-memory candidate
        index) to rebuild the Candidate needed for evidence collection —
        this is what lets the same call work whether it's made
        immediately after run() in the same process, or later via
        `crossforge --review report.json` in a fresh process that never
        ran the scan itself. See CandidateSnapshot's docstring in
        core/authorized_action_gate.py.

        Raises ValueError if proposal_id doesn't exist, was already
        executed/declined, or has no matching finding to upgrade.
        """
        proposal = next(
            (p for p in report.pending_proposals if p.proposal_id == proposal_id), None
        )
        if proposal is None:
            raise ValueError(f"No pending proposal with id {proposal_id!r}")
        if proposal.status != "AWAITING_REVIEW":
            raise ValueError(
                f"Proposal {proposal_id!r} is already {proposal.status!r} — "
                "each proposal can only be executed or declined once."
            )
        finding = next(
            (f for f in report.findings if f.details.get("candidate_id") == proposal.candidate_id),
            None,
        )
        if finding is None:
            raise ValueError(
                f"No existing finding for candidate {proposal.candidate_id!r} — "
                "run_authorized_evidence() upgrades an existing TENTATIVE/FIRM "
                "finding, it does not create one from scratch."
            )

        # The only call in this codebase permitted to reach live evidence
        # methods post-gate — see AuthorizedActionGate.execute()'s
        # operator-identity requirement. cand=None -> reconstructed from
        # proposal.candidate_snapshot.
        evidence = await self._gate.execute(
            proposal, approved_methods=approved_methods, operator=operator,
            internal_addrs=proposal.oob_internal_addrs,
        )
        cand = reconstruct_candidate(proposal.candidate_snapshot)

        registry = get_registry()
        open_ports: list[int] = []
        for art in evidence:
            open_ports.extend(art.extra.get("open_ports", []))
        known_exploits = registry.lookup(open_ports) if open_ports else []

        # Pivot suggestions from the evidence just collected — proposed
        # only, never queued. Operator reviews these in a follow-up call
        # to AuthorizedActionGate.approve_pivots() + a separate,
        # explicit re-run, exactly like the initial evidence approval.
        dns_rebind: list[str] = []  # not re-derived here; already surfaced pre-gate in Phase 7
        suggested_pivots = self._gate.propose_pivots(
            cand, evidence, proposal.oob_internal_addrs, dns_rebind,
            current_hop=cand.hop_count, max_hops=self._max_hops,
        )

        tier = scoring.determine_tier(
            [True], proposal.signal_summary.get("has_oob", False),
            evidence, chained=False, candidate=cand, known_exploits=known_exploits,
        )
        if tier is None:
            proposal.status = "EXECUTED"
            return finding

        s = scoring.score(tier)
        finding.severity     = s["severity"]
        finding.confidence    = s["confidence"]
        finding.cvss_vector   = s["cvss_vector"]
        finding.confidence_tier = tier.value
        finding.known_exploit_refs = [
            {"cve": e.cve, "service": e.service, "escalate_to": e.escalate_to}
            for e in known_exploits
        ] if known_exploits else finding.known_exploit_refs
        finding.details["authorized_evidence"] = {
            "operator":            operator,
            "approved_methods":    list(approved_methods),
            "evidence_types":      [a.evidence_type for a in evidence],
            "evidence_summaries":  [a.summary for a in evidence],
            "evidence_paths":      [a.saved_path for a in evidence if a.saved_path],
            "suggested_pivots":    [p.host for p in suggested_pivots],
            "upgraded_at":         datetime.now(timezone.utc).isoformat(),
        }
        return finding

    # Phase 6 gate  [P0-FIX]
    # ------------------------------------------------------------------

    def _warrants_evidence(
        self, suspicious: list, has_oob: bool, cand: Candidate
    ) -> bool:
        if has_oob:
            return True
        if cand.spa_catchall:
            return False
        for r in suspicious:
            ec = r.error_class or ""
            if ec in ("connection_refused", "timeout", "success_foreign"):
                return True
            # External DNS failure only (not loopback probes)
            if ec == "dns_failure" and r.payload:
                if not _INTERNAL_RE.search(r.payload):
                    return True
        return False

    # ------------------------------------------------------------------
    # Pivot candidate builder
    # ------------------------------------------------------------------

    def _make_pivot_candidates(self, pivot) -> list[Candidate]:
        from core.models import ParamLocation
        cands = []
        host  = pivot.host
        for param in ["url", "target", "src", "endpoint"]:
            c = Candidate(
                target_url=f"http://{host}/",
                method="GET",
                parameter=param,
                param_location=ParamLocation.QUERY,
                original_value="",
                hop_count=pivot.hop_count,
            )
            cands.append(c)
        return cands


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_label(cand: Candidate) -> str:
    """
    Build a display label that truncates the URL PATH from the right,
    preserving the scheme+host — avoids the '://localhost' truncation bug.
    """
    try:
        import httpx
        u = httpx.URL(cand.target_url)
        host = f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")
        path = u.path or "/"
    except Exception:
        host = ""
        path = cand.target_url

    max_path = 35
    if len(path) > max_path:
        path = "…" + path[-(max_path - 1):]
    return f"{cand.method} {host}{path}::{cand.parameter}"


def _is_login_redirect(baseline) -> bool:
    """Return True if the baseline redirect chain points to a login endpoint."""
    for tgt in (baseline.redirect_targets or []):
        if _LOGIN_REDIRECT_RE.search(tgt):
            return True
    return False
