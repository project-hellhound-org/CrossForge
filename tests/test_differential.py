"""
Regression tests for the differential scorer (core/differential.py).

Context: CrossForge's ContextualSSRFDifferentialDetector was flagging
virtually any endpoint that reflected its input at all — logging, "received:
<val>" echoes, form re-population — as an SSRF anomaly, because it compared
a real payload (e.g. "http://127.0.0.1/", ~18 chars) against a baseline
established with an empty original_value. Any length increase in the
payload showed up as a content-length swing regardless of whether the
server made a different network decision.

Reproduced live against a non-vulnerable Flask stub (see /home/claude/work
in the session that produced this file) before the fix: composite_z=10.00
(the hard cap) on 8 of 9 probed candidates. After the fix: 0.

These tests pin that behavior at the unit level — synthetic
BaselineProfile/ProbeResult objects, no live server required — plus a
true-positive case confirming a genuine internal-content leak still gets
flagged, so the fix can't silently regress into "flags nothing" either.
"""
import statistics
import pytest

from core.models import BaselineProfile, ProbeResult
from core.differential import score_result, is_suspicious, DIFFERENTIAL_MARGIN


def _baseline(lengths, timings, dominant_status=200):
    bl = BaselineProfile(
        status_codes=[dominant_status] * len(lengths),
        content_lengths=lengths,
        timings=timings,
    )
    bl.content_length_mean   = statistics.mean(lengths)
    bl.content_length_stddev = max(statistics.pstdev(lengths), 8.0)  # matches [FIX] floor
    bl.timing_mean           = statistics.mean(timings)
    bl.timing_stddev         = max(statistics.pstdev(timings), 0.05)
    bl.dominant_status       = dominant_status
    bl.dominant_redirect_depth = 0
    return bl


def _result(payload, status, length, elapsed, category="internal_loopback"):
    return ProbeResult(
        candidate_id="test", payload=payload, payload_category=category,
        status_code=status, content_length=length, elapsed=elapsed,
        redirect_depth=0, redirect_chain=[], headers={}, body_snippet="",
    )


def test_reflection_only_endpoint_is_not_flagged():
    """
    An endpoint that just echoes its url param (no real SSRF) should not
    be flagged: the real payload and its shape-matched control both
    inflate the response by roughly the same amount, so the differential
    margin correctly stays quiet. This is the exact shape of the bug
    reproduced against the non-vulnerable stub target.
    """
    baseline = _baseline(lengths=[99, 98, 99, 99, 98], timings=[0.01, 0.01, 0.011, 0.01, 0.012])

    real = _result("http://169.254.169.254/latest/meta-data/", status=200, length=139, elapsed=0.012)
    score_result(real, baseline)

    control = _result("http://198.51.100.20/latest/meta-data/0", status=200, length=137, elapsed=0.013,
                       category="cloud_metadata_control")
    score_result(control, baseline)

    real.control_composite_z      = control.composite_z
    real.control_composite_z_raw  = control.composite_z_raw
    real.control_structural_z_raw = control.structural_z_raw

    # Pre-fix, this composite_z alone (via the old empty-baseline comparison)
    # would have been large enough to get flagged. Post-fix, the margin
    # check against the shape-matched control correctly suppresses it.
    assert real.composite_z > 0             # still some deviation from baseline...
    assert not is_suspicious(real)          # ...but correctly not "suspicious"


def test_genuine_internal_leak_is_still_flagged():
    """
    A real SSRF that leaks substantially more content from an internal
    target than its external control does must still be flagged — the
    fix must not just suppress everything.
    """
    baseline = _baseline(lengths=[49, 49, 49, 48, 49], timings=[0.003, 0.003, 0.004, 0.003, 0.003])

    real = _result("http://127.0.0.1:5001/", status=200, length=321, elapsed=0.031)
    score_result(real, baseline)

    control = _result("http://203.0.113.10:5001/", status=502, length=92, elapsed=0.73,
                       category="internal_loopback_control")
    score_result(control, baseline)

    real.control_composite_z      = control.composite_z
    real.control_composite_z_raw  = control.composite_z_raw
    real.control_structural_z_raw = control.structural_z_raw

    assert is_suspicious(real)
    assert (real.structural_z_raw - real.control_structural_z_raw) >= DIFFERENTIAL_MARGIN


def test_untargeted_category_uses_unpaired_path():
    """
    Categories outside TARGET_CLASS_CATEGORIES (e.g. scheme-confusion
    payloads) never get a control attached, and must still be caught via
    the original 2-dimension composite path when the app genuinely
    behaves differently (both status AND content length diverge).
    """
    baseline = _baseline(lengths=[49] * 5, timings=[0.003] * 5)

    result = _result("file:///etc/hostname", status=502, length=137, elapsed=0.03,
                      category="scheme_file")
    score_result(result, baseline)

    assert result.control_composite_z is None
    assert is_suspicious(result)  # status + content-length both diverge from baseline
