"""
tests/calibration/test_infranoise_suppression.py
===================================================
Validates InfraNoiseTracker suppression behaviour:

  ✓ Does NOT suppress when different params produce anomalies (real multi-param SSRF)
  ✓ Does NOT suppress when same param produces anomalies on different endpoints
  ✓ DOES suppress when the same pattern appears across ALL params on ALL endpoints
  ✓ DOES suppress when timing spikes are uniform (CDN/infra noise)
"""

import pytest
from core.baseline import InfraNoiseTracker, BaselineProfile, _TIMING_NOISE_THRESHOLD
from core.models import Candidate, ParamLocation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_candidate(url: str, param: str = "url", cid: str = "") -> Candidate:
    """Create a minimal candidate for testing."""
    c = Candidate(
        target_url=url,
        method="GET",
        parameter=param,
        param_location=ParamLocation.QUERY,
    )
    if cid:
        c.candidate_id = cid
    return c


def _make_profile(*, spike: bool = False) -> BaselineProfile:
    """Create a BaselineProfile. If spike=True, includes a timing spike."""
    if spike:
        # Mean = 0.1, stddev = 0.05 (floor), outlier at 5.0
        # z_score(5.0, 0.1, 0.05) = 98.0 → definitely > 2.0 threshold
        return BaselineProfile(
            timings=[0.1, 0.1, 0.1, 0.1, 5.0],
            content_lengths=[1000, 1000, 1000, 1000, 1000],
            status_codes=[200, 200, 200, 200, 200],
            redirect_depths=[0, 0, 0, 0, 0],
            timing_mean=0.1,
            timing_stddev=0.05,
            content_length_mean=1000.0,
            content_length_stddev=20.0,
            dominant_status=200,
            dominant_redirect_depth=0,
        )
    else:
        # Normal, stable baseline
        return BaselineProfile(
            timings=[0.1, 0.11, 0.09, 0.1, 0.1],
            content_lengths=[1000, 1000, 1001, 1000, 999],
            status_codes=[200, 200, 200, 200, 200],
            redirect_depths=[0, 0, 0, 0, 0],
            timing_mean=0.1,
            timing_stddev=0.01,
            content_length_mean=1000.0,
            content_length_stddev=20.0,
            dominant_status=200,
            dominant_redirect_depth=0,
        )


# ---------------------------------------------------------------------------
# Test: Does NOT suppress real multi-param SSRF
# ---------------------------------------------------------------------------

def test_different_params_same_endpoint_not_suppressed():
    """
    If 3 DIFFERENT params on the same endpoint each show timing spikes,
    this is potentially real multi-param SSRF, not infra noise.
    InfraNoiseTracker should NOT suppress because some candidates on
    the same endpoint are clean (no spike).
    """
    tracker = InfraNoiseTracker(noise_threshold=3)

    # 3 candidates with spikes (different params)
    c1 = _make_candidate("http://target.com/api/fetch", "url", "c1")
    c2 = _make_candidate("http://target.com/api/fetch", "src", "c2")
    c3 = _make_candidate("http://target.com/api/fetch", "callback", "c3")
    # 1 candidate WITHOUT spike on same endpoint
    c4 = _make_candidate("http://target.com/api/fetch", "format", "c4")

    tracker.record(c1, _make_profile(spike=True))
    tracker.record(c2, _make_profile(spike=True))
    tracker.record(c3, _make_profile(spike=True))
    tracker.record(c4, _make_profile(spike=False))  # breaks the "all spiked" condition

    flagged = tracker.propagate_flags([c1, c2, c3, c4])

    # Should NOT be flagged — not all candidates spiked
    assert flagged == 0
    assert not c1.infra_noise_detected
    assert not c3.infra_noise_detected


# ---------------------------------------------------------------------------
# Test: Does NOT suppress different endpoints
# ---------------------------------------------------------------------------

def test_same_param_different_endpoints_not_suppressed():
    """
    If the same param produces spikes on DIFFERENT endpoints,
    this is real per-endpoint SSRF, not infra noise.
    """
    tracker = InfraNoiseTracker(noise_threshold=3)

    # 3 candidates on endpoint A — all spike
    a1 = _make_candidate("http://target.com/api/fetch", "url", "a1")
    a2 = _make_candidate("http://target.com/api/fetch", "url", "a2")
    a3 = _make_candidate("http://target.com/api/fetch", "url", "a3")

    # 3 candidates on endpoint B — mixed
    b1 = _make_candidate("http://target.com/api/proxy", "url", "b1")
    b2 = _make_candidate("http://target.com/api/proxy", "url", "b2")
    b3 = _make_candidate("http://target.com/api/proxy", "url", "b3")

    tracker.record(a1, _make_profile(spike=True))
    tracker.record(a2, _make_profile(spike=True))
    tracker.record(a3, _make_profile(spike=True))
    tracker.record(b1, _make_profile(spike=True))
    tracker.record(b2, _make_profile(spike=False))  # breaks endpoint B noise
    tracker.record(b3, _make_profile(spike=True))

    all_candidates = [a1, a2, a3, b1, b2, b3]
    flagged = tracker.propagate_flags(all_candidates)

    # Endpoint A: all 3 spiked → flagged as noise
    assert a1.infra_noise_detected
    assert a2.infra_noise_detected
    assert a3.infra_noise_detected

    # Endpoint B: not all spiked → NOT flagged
    assert not b1.infra_noise_detected
    assert not b2.infra_noise_detected

    # Only 3 flagged (endpoint A), not 6
    assert flagged == 3


# ---------------------------------------------------------------------------
# Test: DOES suppress uniform infra noise
# ---------------------------------------------------------------------------

def test_all_candidates_same_endpoint_all_spike_suppressed():
    """
    When ALL candidates on the same endpoint exhibit timing spikes,
    and the count meets the noise_threshold, it's infra noise.
    InfraNoiseTracker SHOULD suppress all of them.
    """
    tracker = InfraNoiseTracker(noise_threshold=3)

    candidates = []
    for i in range(5):
        c = _make_candidate("http://target.com/api/webhook", "url", f"c{i}")
        tracker.record(c, _make_profile(spike=True))
        candidates.append(c)

    flagged = tracker.propagate_flags(candidates)

    assert flagged == 5
    for c in candidates:
        assert c.infra_noise_detected
        assert "infra_noise" in c.confidence_reduction_flags


def test_below_threshold_not_suppressed():
    """
    Even if all candidates spike, if count < noise_threshold, don't suppress.
    """
    tracker = InfraNoiseTracker(noise_threshold=3)

    # Only 2 candidates — below threshold of 3
    c1 = _make_candidate("http://target.com/api/webhook", "url", "c1")
    c2 = _make_candidate("http://target.com/api/webhook", "src", "c2")

    tracker.record(c1, _make_profile(spike=True))
    tracker.record(c2, _make_profile(spike=True))

    flagged = tracker.propagate_flags([c1, c2])

    assert flagged == 0
    assert not c1.infra_noise_detected


# ---------------------------------------------------------------------------
# Test: No spikes → no suppression
# ---------------------------------------------------------------------------

def test_no_spikes_no_suppression():
    """If no candidates have timing spikes, nothing is suppressed."""
    tracker = InfraNoiseTracker(noise_threshold=3)

    candidates = []
    for i in range(5):
        c = _make_candidate("http://target.com/api/webhook", "url", f"c{i}")
        tracker.record(c, _make_profile(spike=False))
        candidates.append(c)

    flagged = tracker.propagate_flags(candidates)

    assert flagged == 0
    assert tracker.noisy_endpoint_count == 0


# ---------------------------------------------------------------------------
# Test: Multiple noisy endpoints tracked independently
# ---------------------------------------------------------------------------

def test_multiple_noisy_endpoints_independent():
    """Each endpoint is tracked independently — noise on one doesn't affect another."""
    tracker = InfraNoiseTracker(noise_threshold=3)

    # Endpoint A: all spike (noisy)
    for i in range(3):
        c = _make_candidate("http://target.com/api/a", "url", f"a{i}")
        tracker.record(c, _make_profile(spike=True))

    # Endpoint B: mixed (not noisy)
    for i in range(3):
        c = _make_candidate("http://target.com/api/b", "url", f"b{i}")
        tracker.record(c, _make_profile(spike=(i < 2)))  # 2 spike, 1 clean

    assert tracker.noisy_endpoint_count == 1  # Only endpoint A


# ---------------------------------------------------------------------------
# Test: propagate_flags is idempotent
# ---------------------------------------------------------------------------

def test_propagate_flags_idempotent():
    """Calling propagate_flags twice doesn't double-add reduction flags."""
    tracker = InfraNoiseTracker(noise_threshold=3)

    candidates = []
    for i in range(3):
        c = _make_candidate("http://target.com/api/webhook", "url", f"c{i}")
        tracker.record(c, _make_profile(spike=True))
        candidates.append(c)

    tracker.propagate_flags(candidates)
    tracker.propagate_flags(candidates)  # second call

    for c in candidates:
        # Should still only have one "infra_noise" flag, not two
        assert c.confidence_reduction_flags.count("infra_noise") == 1
