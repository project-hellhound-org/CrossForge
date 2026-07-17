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
from pathlib import Path

import yaml

from core.models import (
    ScanMode, ScanReport, ConfidenceTier, EvidenceArtifact, Candidate,
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
from core.differential   import probe_candidate, is_suspicious, describe_signature
from core.oob_hub        import OOBHub
from core.evidence_engine import (
    check_cloud_metadata, check_kubernetes_api, check_ecs_metadata,
    check_oracle_cloud, fingerprint_internal_service,
    check_file_read, check_crlf_injection, build_port_state_map,
)
from core.chaining       import extract_pivot_targets, detect_dns_rebinding
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

        oob_cfg     = self.cfg.get("oob", {})
        server_url  = oob_cfg.get("server_url")
        self._oob   = (
            OOBHub(server_url, oob_cfg.get("poll_interval", 5.0))
            if server_url else None
        )

        self._output_dir = Path(self.cfg.get("output", {}).get("dir", "reports"))
        self._output_dir.mkdir(exist_ok=True)
        self._max_hops   = self.cfg.get("chaining", {}).get("max_hops", 3)

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

        recon_rows = [
            ("Source",              color("Native crawl" if crawled_spider_data is not None else "Supplied spider file", C.BWHITE)),
            ("Endpoints/candidates", color(str(len(candidates)), C.BWHITE, C.BOLD)),
            ("OpenAPI-derived",      color(str(openapi_count), C.BBLUE if openapi_count else C.DIM)),
            ("GraphQL-derived",      color(str(graphql_count), C.BBLUE if graphql_count else C.DIM)),
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
        self._exploit_stats   = {"evidence_artifacts": Counter()}
        self._postexploit_stats = {"chains_built": 0, "pivot_targets_found": 0, "dns_rebinds_detected": 0}

        for i, cand in enumerate(active):
            label_str = _short_label(cand)
            status.update(
                phase=f"scanning",
                detail=label_str,
                done=i, total=len(active),
                findings=sum(findings_count.values()),
            )
            await self._process_candidate(
                cand, report, pivot_queue, findings_count, status
            )
            status.inc_requests()

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
        lifecycle_result(4, [
            ("Anomalies found",             color(str(self._detect_stats["anomalies_found"]), C.BYELLOW if self._detect_stats["anomalies_found"] else C.DIM)),
            ("OOB interactions confirmed",  color(str(self._detect_stats["oob_interactions_confirmed"]), C.BRED, C.BOLD) if self._detect_stats["oob_interactions_confirmed"] else color("0", C.DIM)),
        ])

        top_evidence = self._exploit_stats["evidence_artifacts"].most_common(5)
        lifecycle_header(5)
        lifecycle_result(5, [
            ("Evidence artifacts collected", color(str(sum(self._exploit_stats["evidence_artifacts"].values())), C.BRED, C.BOLD)),
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
        summary_rows = [
            ("Duration",            color(f"{elapsed:.1f}s", C.BWHITE)),
            ("Candidates scanned",  color(str(len(active)), C.BWHITE)),
        ]
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
    ) -> None:
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

        suspicious = [r for r in results if is_suspicious(r, cand)]
        if suspicious:
            self._detect_stats["anomalies_found"] += 1
        has_signal = bool(suspicious) or (self._oob and self._oob.has_interaction(cid))
        if not has_signal:
            return   # clean — no further phases

        # Phase 5: OOB
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
            await asyncio.sleep(self._oob.poll_interval)
            has_oob     = self._oob.has_interaction(cid)
            async_pat   = self._oob.is_async_pattern(cid)
            pivot_addrs = self._oob.internal_pivot_targets(cid)
            if has_oob:
                status.inc_findings()
                self._detect_stats["oob_interactions_confirmed"] += 1

        # Phase 6: Evidence (gated)
        status.update(phase="6-evidence")
        evidence: list[EvidenceArtifact] = []

        if self._warrants_evidence(suspicious, has_oob, cand):
            for checker in (
                check_cloud_metadata,
                check_kubernetes_api,
                check_ecs_metadata,
                check_oracle_cloud,
            ):
                art = await checker(self._client, cand)
                if art:
                    evidence.append(art)
                    status.inc_findings()

            psm = await build_port_state_map(self._client, cand, "127.0.0.1")
            if psm:
                evidence.append(psm)

            for addr in pivot_addrs:
                art = await fingerprint_internal_service(self._client, cand, addr)
                if art:
                    evidence.append(art)

            art = await check_file_read(self._client, cand)
            if art:
                evidence.append(art)

            art = await check_crlf_injection(self._client, cand)
            if art:
                evidence.append(art)

            for art in evidence:
                if art.evidence_type == "cloud_metadata_schema":
                    escalated = await feedback.maybe_escalate_imdsv2(
                        self._client, cand, art
                    )
                    if escalated:
                        evidence.append(escalated)
                    break

        for art in evidence:
            self._exploit_stats["evidence_artifacts"][art.evidence_type] += 1

        # Phase 7: Chaining
        status.update(phase="7-chain")
        dns_rebind: list[str] = []
        for r in suspicious:
            if r.resolved_ip and cand.baseline and detect_dns_rebinding(
                cand.baseline.baseline_resolved_ip, r.resolved_ip
            ):
                dns_rebind.append(r.resolved_ip)

        pivots  = extract_pivot_targets(
            cand, evidence, pivot_addrs, dns_rebind,
            current_hop=cand.hop_count + 1,
            max_hops=self._max_hops,
        )
        pivot_queue.extend(pivots)
        chained = bool(pivots)
        if chained:
            self._postexploit_stats["chains_built"] += 1
            self._postexploit_stats["pivot_targets_found"] += len(pivots)
        self._postexploit_stats["dns_rebinds_detected"] += len(dns_rebind)

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

        # Inject confidence_tier for finding card display
        finding.confidence_tier = tier.value  # type: ignore[attr-defined]

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
            feedback.propagate_pattern(cand, [])
            feedback.propagate_cloud_container_pattern(evidence, [])
            if known_exploits:
                from urllib.parse import urlparse
                tgt_host = urlparse(cand.target_url).hostname or ""
                feedback.propagate_known_exploits(evidence, [], tgt_host)

        if self._oob:
            h = self._oob.get_health()
            status.update(
                findings=sum(findings_count.values()),
            )

    # ------------------------------------------------------------------
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
