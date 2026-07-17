"""
HELLHOUND SSRF v5.0 - Phase 1: Multi-Dimensional Baseline Establishment
=========================================================================
v5 additions:
  [v5-NEW] Infrastructure-noise detection (borrowed from Invicti's confidence-
           reduction signal model). If the same anomaly pattern appears on
           ≥3 other candidates for the SAME endpoint, it's load-balancer
           variance / CDN edge routing — not SSRF. The endpoint is flagged
           and all its candidates get infra_noise_detected=True.
  [P1-FIX] timing_stddev floor raised from 0.01 → 0.05 (seconds) to
           prevent single-millisecond variance from producing massive z-scores
           on fast endpoints.
  [v5-NEW] Endpoint-level anomaly tracker (InfraNoiseTracker) consumable
           across the full candidate queue to propagate infra_noise flags
           before Phase 4 starts.
"""

from __future__ import annotations
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from core.models import BaselineProfile, Candidate

# Number of clean requests per candidate for baseline establishment
BASELINE_SAMPLES = 5

# Minimum stddev floors to prevent tiny-variance → huge z-score
_TIMING_STDDEV_FLOOR    = 0.05   # 50 ms — [P1-FIX] raised from 0.01
_CONTENT_STDDEV_FLOOR   = 8.0    # [FIX] raised from 1 byte — see finalize()

# Threshold for "anomalous baseline sample" — used by InfraNoiseTracker
_TIMING_NOISE_THRESHOLD = 2.0    # z-score units


# ---------------------------------------------------------------------------
# Core baseline collection
# ---------------------------------------------------------------------------

async def establish_baseline(client, candidate: Candidate) -> BaselineProfile:
    """
    Sends BASELINE_SAMPLES clean (unmodified original_value) requests and
    builds a per-dimension statistical profile.
    """
    profile = BaselineProfile()

    for _ in range(BASELINE_SAMPLES):
        result = await client.send(
            candidate,
            payload_value=candidate.original_value,
            payload_category="baseline",
        )
        profile.status_codes.append(result.status_code)
        profile.content_lengths.append(result.content_length)
        profile.timings.append(result.elapsed)
        profile.redirect_depths.append(result.redirect_depth)
        profile.redirect_targets.append(",".join(result.redirect_chain))
        profile.headers_signature.append({
            "server":        result.headers.get("Server", ""),
            "content_type":  result.headers.get("Content-Type", ""),
            "cache_control": result.headers.get("Cache-Control", ""),
        })
        if profile.baseline_resolved_ip is None and result.resolved_ip:
            profile.baseline_resolved_ip = result.resolved_ip

    finalize(profile)
    return profile


def finalize(profile: BaselineProfile) -> BaselineProfile:
    """Computes derived statistics from raw baseline samples."""
    if profile.timings:
        profile.timing_mean   = statistics.mean(profile.timings)
        # [P1-FIX] raised floor to 50 ms
        profile.timing_stddev = max(
            statistics.pstdev(profile.timings),
            _TIMING_STDDEV_FLOOR,
        )
    if profile.content_lengths:
        profile.content_length_mean   = statistics.mean(profile.content_lengths)
        # [FIX] Floor scales with response size instead of a flat 1 byte.
        # A fixed 1-byte floor meant ANY endpoint that reflects its input
        # at all (logs, "received: <val>" echoes, form re-population —
        # none of which are SSRF) produced a content-length z-score in
        # the dozens just from the payload string being longer than the
        # empty baseline value. 2% of the mean response size (min 8 bytes)
        # absorbs normal echo/jitter noise while still catching a
        # genuinely different response shape (e.g. a full page fetched
        # vs a JSON error).
        profile.content_length_stddev = max(
            statistics.pstdev(profile.content_lengths),
            max(_CONTENT_STDDEV_FLOOR, profile.content_length_mean * 0.02),
        )
    if profile.status_codes:
        profile.dominant_status = Counter(profile.status_codes).most_common(1)[0][0]
    if profile.redirect_depths:
        profile.dominant_redirect_depth = Counter(profile.redirect_depths).most_common(1)[0][0]
    return profile


def z_score(value: float, mean: float, stddev: float) -> float:
    """Standard z-score with a guarded stddev floor."""
    if stddev <= 0:
        stddev = 0.01
    return (value - mean) / stddev


# ---------------------------------------------------------------------------
# [v5-NEW] Infrastructure-noise tracker
# ---------------------------------------------------------------------------

@dataclass
class _EndpointAnomaly:
    timing_spikes: int = 0      # baseline samples with high timing variance
    total_candidates: int = 0


class InfraNoiseTracker:
    """
    Tracks baseline timing anomaly patterns per endpoint URL.

    RATIONALE (Invicti model):
    If endpoint /api/webhook has 5 candidates, and ALL 5 show a >2 σ
    timing spike in their Phase 1 baseline, that timing spike is NOT caused
    by SSRF payload — it's CDN variance / server-side rate limiting.
    Promoting those candidates to Phase 6 evidence would generate 5 false
    CERTAIN findings.

    Usage inside agent.py:
        tracker = InfraNoiseTracker()
        for candidate in queue:
            profile = await establish_baseline(client, candidate)
            tracker.record(candidate, profile)
        tracker.propagate_flags(queue)  # mutates candidates in-place
    """

    def __init__(self, noise_threshold: int = 3):
        """
        Parameters
        ----------
        noise_threshold : int
            Minimum number of candidates on the same endpoint that must all
            show timing anomalies before the endpoint is flagged as
            infrastructure noise. Default: 3.
        """
        self._noise_threshold = noise_threshold
        # endpoint_url → _EndpointAnomaly
        self._stats: dict[str, _EndpointAnomaly] = defaultdict(
            lambda: _EndpointAnomaly()
        )
        # endpoint_url → candidate_ids that showed timing spikes
        self._spike_candidates: dict[str, list[str]] = defaultdict(list)

    def record(self, candidate: Candidate, profile: BaselineProfile) -> None:
        """
        Record whether this candidate's baseline timing shows high variance.
        Call once per candidate after establish_baseline().
        """
        key = _endpoint_key(candidate.target_url)
        state = self._stats[key]
        state.total_candidates += 1

        if _has_timing_spike(profile):
            state.timing_spikes += 1
            self._spike_candidates[key].append(candidate.candidate_id)

    def propagate_flags(self, candidates: list[Candidate]) -> int:
        """
        Mutates candidates in-place, setting infra_noise_detected=True
        on all candidates belonging to endpoints that meet the noise threshold.

        Returns the number of candidates flagged.
        """
        noisy_endpoints: set[str] = set()
        for key, state in self._stats.items():
            # Flag if ALL candidates on this endpoint spiked, and there are
            # enough of them to distinguish infra noise from true SSRF signal
            if (state.timing_spikes >= self._noise_threshold
                    and state.timing_spikes == state.total_candidates):
                noisy_endpoints.add(key)

        flagged = 0
        for c in candidates:
            key = _endpoint_key(c.target_url)
            if key in noisy_endpoints:
                c.infra_noise_detected = True
                if "infra_noise" not in c.confidence_reduction_flags:
                    c.confidence_reduction_flags.append("infra_noise")
                flagged += 1

        return flagged

    @property
    def noisy_endpoint_count(self) -> int:
        return sum(
            1 for state in self._stats.values()
            if (state.timing_spikes >= self._noise_threshold
                and state.timing_spikes == state.total_candidates)
        )


def _has_timing_spike(profile: BaselineProfile) -> bool:
    """
    Returns True if any single baseline sample is >TIMING_NOISE_THRESHOLD σ
    from the mean — indicating high endpoint latency variance.
    """
    if not profile.timings or profile.timing_stddev <= 0:
        return False
    for t in profile.timings:
        if abs(z_score(t, profile.timing_mean, profile.timing_stddev)) > _TIMING_NOISE_THRESHOLD:
            return True
    return False


def _endpoint_key(url: str) -> str:
    """Normalize URL to scheme+host+path for grouping (strip query/fragment)."""
    try:
        import httpx
        u = httpx.URL(url)
        return f"{u.scheme}://{u.host}{':' + str(u.port) if u.port else ''}{u.path}"
    except Exception:
        return url.split("?")[0].split("#")[0]
