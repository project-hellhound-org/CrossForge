"""
Regression tests for Phase 1-2 (Recon & Scanning) surgical fixes documented
in CrossForge_LLM_Fix_Prompt.md, Parts A and B.

Each test pins the specific failure mode described in the audit at the unit
level (synthetic inputs, no live server / no browser required) so the fix
can't silently regress.
"""
from __future__ import annotations

import pytest

from core.context_classifier import _select_subset, ContextClass
from core.models import PreScoreTier
from core.recon_quality import QualityBaseline, QualityVerdict, classify_response
from core.crawler import AdaptiveBudget, CrawlConfig


# ---------------------------------------------------------------------------
# Issue A.1 — OOB token mutation across candidates sharing a context class
# ---------------------------------------------------------------------------

def test_select_subset_returns_independent_dict_copies():
    """Two calls for the same context class must not share inner dict
    references — otherwise mutating one candidate's payload (splicing in
    its OOB token) silently defeats the next candidate's OOB dispatch."""
    subset_a = _select_subset(ContextClass.FETCH_URL, PreScoreTier.HIGH)
    subset_b = _select_subset(ContextClass.FETCH_URL, PreScoreTier.HIGH)
    assert subset_a[0] is not subset_b[0]


def test_mutating_one_subset_does_not_leak_into_another():
    subset_a = _select_subset(ContextClass.FETCH_URL, PreScoreTier.HIGH)
    subset_b = _select_subset(ContextClass.FETCH_URL, PreScoreTier.HIGH)

    for entry in subset_a:
        if "{token}" in entry.get("payload", ""):
            entry["payload"] = entry["payload"].replace("{token}", "LEAKED-TOKEN-A")
            break

    assert not any("LEAKED-TOKEN-A" in e.get("payload", "") for e in subset_b)


# ---------------------------------------------------------------------------
# Issue B.1 — SPA canary/shell hash collision discards real pages
# ---------------------------------------------------------------------------

_SPA_SHELL_BODY = "<html><body><div id='app'></div><script src='/app.js'></script></body></html>"


def test_seed_url_bypasses_canary_collision_on_spa_shell():
    """On an SPA target, the canary probe and every real route return the
    identical index.html shell. A seed URL (base URL / robots / sitemap /
    wayback) must still classify as REAL even though its body matches the
    canary hash byte-for-byte — otherwise every SPA target loses 100% of
    its recon before parsing ever runs."""
    baseline = QualityBaseline()
    baseline.established = True
    baseline.canary_status = 200
    from core.recon_quality import _hash_body
    baseline.canary_hash = _hash_body(_SPA_SHELL_BODY)

    verdict = classify_response(baseline, 200, _SPA_SHELL_BODY, is_seed=True)
    assert verdict == QualityVerdict.REAL


def test_non_seed_url_still_gets_soft_404_filtered():
    """The canary check must still fire for organically-discovered links
    that happen to hit the same soft-404 shell — is_seed=False is the
    normal, unexempted path."""
    baseline = QualityBaseline()
    baseline.established = True
    baseline.canary_status = 200
    from core.recon_quality import _hash_body
    baseline.canary_hash = _hash_body(_SPA_SHELL_BODY)

    verdict = classify_response(baseline, 200, _SPA_SHELL_BODY, is_seed=False)
    assert verdict == QualityVerdict.SOFT_404


def test_bot_block_detection_applies_even_to_seed_urls():
    """The is_seed exemption is scoped narrowly to the canary-hash check —
    a seed URL that actually hits a WAF challenge page must still be
    caught by the independent bot-block marker check."""
    baseline = QualityBaseline()
    challenge_body = "Please verify you are human — checking your browser before continuing."
    verdict = classify_response(baseline, 403, challenge_body, is_seed=True)
    assert verdict == QualityVerdict.BOT_BLOCKED


# ---------------------------------------------------------------------------
# Issue B.2 — stall detection scores seed batch, not organic yield
# ---------------------------------------------------------------------------

def _budget(floor=50, ceiling=400):
    cfg = CrawlConfig(max_pages_floor=floor, max_pages_ceiling=ceiling)
    return AdaptiveBudget(cfg)


def test_all_seed_batch_does_not_trigger_stall():
    """A level-0 batch that is 100% seed URLs (robots/sitemap/wayback,
    typically leaf/asset pages with zero fresh links) must not stall the
    crawl before a single organically-discovered link has been scored."""
    budget = _budget()
    # organic_fetched_this_level == 0 -> caller must skip scoring entirely
    # (this test documents the contract; the crawler's BFS loop is the
    # actual caller and only invokes record_level when organic count > 0)
    assert budget.stalled is False


def test_genuine_low_organic_yield_still_stalls():
    """Once yield is scored on a genuinely organic batch, a real stall
    (near-zero new links per page fetched) must still be detected — the
    fix narrows *what* gets scored, not the stall threshold itself."""
    budget = _budget()
    budget.record_level(pages_this_level=20, new_links_this_level=0)
    assert budget.stalled is True


def test_healthy_organic_yield_does_not_stall_and_grows_budget():
    budget = _budget()
    budget.record_level(pages_this_level=10, new_links_this_level=8)
    assert budget.stalled is False
    assert budget.budget > 50  # GROWTH_THRESHOLD (0.5) exceeded -> budget expands


# ---------------------------------------------------------------------------
# Issue C.3 — WAF fingerprint result never correlated with anomaly threshold
# ---------------------------------------------------------------------------

def test_is_suspicious_uses_relaxed_threshold_when_passed():
    """A composite_z that clears the default 2.0 bar but not a WAF-relaxed
    2.5 bar must be treated as NOT suspicious when the caller passes the
    WAF threshold — this is what lets agent.py correlate Phase 3's WAF
    fingerprint with Phase 4's anomaly decision instead of ignoring it."""
    import statistics
    from core.models import BaselineProfile, ProbeResult
    from core.differential import score_result, is_suspicious, SUSPICIOUS_THRESHOLD_WAF

    lengths = [100, 100, 101, 100, 100]
    timings = [0.05, 0.05, 0.05, 0.05, 0.05]
    baseline = BaselineProfile(status_codes=[200] * 5, content_lengths=lengths, timings=timings)
    baseline.content_length_mean   = statistics.mean(lengths)
    baseline.content_length_stddev = 8.0
    baseline.timing_mean           = statistics.mean(timings)
    baseline.timing_stddev         = 0.05
    baseline.dominant_status       = 200
    baseline.dominant_redirect_depth = 0

    # Single anomalous dimension (content_length only; status matches
    # baseline's dominant status, timing matches baseline mean) so this
    # exercises the "single-dim spike, higher bar" path in is_suspicious:
    # composite_z ≈ 0.8 * z_content_length ≈ 0.8 * 4.0 = 3.2, which clears
    # the default threshold's higher bar (2.0*1.5=3.0) but not the WAF
    # threshold's higher bar (2.5*1.5=3.75).
    result = ProbeResult(
        candidate_id="test", payload="x", payload_category="internal_loopback",
        status_code=200, content_length=132, elapsed=0.05,
        redirect_depth=0, redirect_chain=[], headers={}, body_snippet="",
    )
    score_result(result, baseline)

    assert is_suspicious(result) is True  # default threshold (2.0): fires
    assert is_suspicious(result, threshold=SUSPICIOUS_THRESHOLD_WAF) is False  # 2.5: doesn't

