"""
HELLHOUND SSRF v5.0 - Phase 4: Active Probing & Differential Analysis
========================================================================
v5 fixes and enhancements:
  [P1-FIX] composite_z HARD CAPPED at 10.0 — prevents a single extreme
           dimension (e.g. 10s timeout → z_timing=500) from dominating
           and promoting noisy candidates to false CERTAIN findings.
  [P1-FIX] 2-DIMENSION NOISE FLOOR — composite_z path requires ≥2
           dimensions to show anomaly (|z| ≥ 1.5). A single-dimension spike
           alone drops to TENTATIVE max and adds a confidence_reduction_flag.
  [P0-FIX] SSRF-SPECIFIC ERROR GATE in is_suspicious() — dns_failure only
           fires the gate when the payload is an EXTERNAL/OOB domain (not
           a loopback probe). This prevents generic DNS failures from
           triggering Phase 6 evidence collection.
  [v5-NEW] Mutation retry: blocked payloads get one mutation attempt via
           the candidate's WAF-specific mutation_chain (unchanged from v4
           but now bounded to 1 variant per blocked payload, not the whole
           chain).
  [v5-NEW] infra_noise_detected candidates are probed with reduced budget
           (LOW-tier subset) regardless of pre_score_tier to conserve budget.
"""

from __future__ import annotations
import re

from core.models import Candidate, ProbeResult, BaselineProfile
from core.baseline import z_score
from core.http_client import HttpClient
from core.payload_engine import apply_mutation_chain, build_control_payload

SUSPICIOUS_THRESHOLD = 2.0
COMPOSITE_Z_CAP      = 10.0          # [P1-FIX]
MIN_ANOMALOUS_DIMS   = 2             # [P1-FIX] noise floor

# [FIX] Minimum required gap between an internal-target payload's
# composite_z and its shape-matched external control's composite_z.
# See build_control_payload() docstring in payload_engine.py for the
# full rationale — this is the check that actually makes this detector
# "differential" between target classes rather than differential against
# an unrelated empty baseline. A candidate that just reflects its input
# will show internal ≈ control (delta ≈ 0) and correctly stay quiet.
# [FIX] Empirically set against a controlled test target: a genuine
# internal-content leak produced structural Δ≈20 vs. its control; probes
# against internal/RFC1918 addresses with nothing listening (i.e. no real
# SSRF) produced noise up to Δ≈4, mostly from block/error pages that embed
# the target host string at a slightly different length than the control's
# decoy host. 8.0 sits comfortably above that noise band. Revisit this
# against real target traffic if a specific app's error pages are unusually
# verbose or bland — see docs/differential-tuning.md follow-up note.
DIFFERENTIAL_MARGIN  = 8.0

# Payload categories that represent "fetch/redirect-to a specific network
# target" — these are the ones where response differences are supposed to
# mean something about reachability, so they get paired with a control.
# Deliberately excludes: oob_canary/oob_dns/oob_generic (scored via OOB
# callback, not response diffing), crlf_* (header-injection confirmation
# is evidence-based, not size-based), file_include payloads (local
# wrapper schemes, no comparable "external" host), and the scheme-
# confusion/encoding-bypass payloads (left as a follow-up — see NOTE
# in core/prescore.py-adjacent docs).
TARGET_CLASS_CATEGORIES = frozenset({
    "internal_loopback", "cloud_metadata", "internal_rfc1918",
    "generic_loopback", "generic_metadata",
    "open_redirect_internal", "open_redirect_metadata",
    "host_loopback", "host_metadata", "host_private",
})

DIMENSION_WEIGHTS = {
    "timing":         1.5,
    "redirect":       1.3,
    "status":         1.0,
    "content_length": 0.8,
}

# Regex for external/OOB domain payloads (not RFC1918 / loopback)
_INTERNAL_IP_RE = re.compile(
    r"(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|::1|localhost)",
    re.I,
)


async def probe_candidate(
    client: HttpClient,
    candidate: Candidate,
) -> list[ProbeResult]:
    """
    Sends every payload in candidate.payload_subset, scores against baseline,
    and attempts one WAF mutation retry for any blocked payload.
    """
    if candidate.baseline is None:
        raise ValueError(
            f"probe_candidate called before baseline established for "
            f"candidate {candidate.candidate_id} "
            f"({candidate.method} {candidate.target_url} :: {candidate.parameter})"
        )

    baseline = candidate.baseline
    results:  list[ProbeResult] = []

    # [v5] Infra-noise candidates get LOW-tier budget regardless of pre_score_tier
    subset = candidate.payload_subset
    if candidate.infra_noise_detected and len(subset) > 2:
        subset = subset[:2]

    for entry in subset:
        payload_value = entry.get("payload", "")
        category      = entry.get("category", "unknown")

        # OOB canary templates are filled by Phase 5, not here
        if "{token}" in payload_value:
            continue

        result = await client.send(
            candidate,
            payload_value=payload_value,
            payload_category=category,
        )
        score_result(result, baseline)
        results.append(result)

        # [FIX] Shape-matched external control pairing — see
        # payload_engine.build_control_payload() and DIFFERENTIAL_MARGIN
        # above. Only for categories that represent a specific network
        # target; the control result itself is never eligible to become
        # a finding, it only exists to calibrate the real result.
        if category in TARGET_CLASS_CATEGORIES and payload_value:
            control_value = build_control_payload(payload_value)
            control_result = await client.send(
                candidate,
                payload_value=control_value,
                payload_category=f"{category}_control",
            )
            score_result(control_result, baseline)
            result.control_composite_z      = control_result.composite_z
            result.control_composite_z_raw  = control_result.composite_z_raw
            result.control_structural_z_raw = control_result.structural_z_raw
            result.control_payload          = control_value

        # ---- WAF mutation retry (1 variant per blocked payload) -----------
        if _is_blocked(result) and candidate.mutation_chain:
            variants = apply_mutation_chain(payload_value, candidate.mutation_chain)
            if variants:
                mutated = await client.send(
                    candidate,
                    payload_value=variants[0],
                    payload_category=f"{category}_mutated",
                )
                score_result(mutated, baseline)
                results.append(mutated)

    return results


def score_result(result: ProbeResult, baseline: BaselineProfile) -> None:
    """Populates per-dimension z-scores and composite_z on `result`."""

    result.z_timing = z_score(
        result.elapsed,
        baseline.timing_mean,
        baseline.timing_stddev,
    )
    result.z_content_length = z_score(
        result.content_length,
        baseline.content_length_mean,
        baseline.content_length_stddev,
    )

    # Status: 0 if matches dominant baseline status, else scaled by severity
    if (baseline.dominant_status is not None
            and result.status_code == baseline.dominant_status):
        result.z_status = 0.0
    else:
        result.z_status = 1.0 if (result.status_code or 200) < 500 else 2.5

    result.z_redirect = abs(result.redirect_depth - baseline.dominant_redirect_depth)

    raw_composite = (
        DIMENSION_WEIGHTS["timing"]         * abs(result.z_timing)
        + DIMENSION_WEIGHTS["redirect"]     * result.z_redirect
        + DIMENSION_WEIGHTS["status"]       * result.z_status
        + DIMENSION_WEIGHTS["content_length"] * abs(result.z_content_length)
    )

    # [FIX] Structural signal excludes timing — see models.ProbeResult
    # docstring for why. This is what the differential-margin gate uses.
    structural_raw = (
        DIMENSION_WEIGHTS["redirect"]         * result.z_redirect
        + DIMENSION_WEIGHTS["status"]         * result.z_status
        + DIMENSION_WEIGHTS["content_length"] * abs(result.z_content_length)
    )
    result.structural_z_raw = structural_raw

    # [P1-FIX] Hard cap at 10.0 for display; raw value kept for [FIX] margin math
    result.composite_z_raw = raw_composite
    result.composite_z     = min(raw_composite, COMPOSITE_Z_CAP)

    if result.error_class in (None, "success"):
        result.error_class = "none"


def is_suspicious(result: ProbeResult, candidate: Candidate | None = None) -> bool:
    """
    Returns True if a result warrants Phase 5/6 follow-up.

    [FIX] Differential-margin gate: if this result was paired with a
      shape-matched external control (result.control_composite_z is not
      None — see build_control_payload()), the internal-target composite_z
      must exceed the control's by DIFFERENTIAL_MARGIN. This is what stops
      "the app echoes whatever I send it" from registering as SSRF: the
      control payload inflates the response by the same amount as the
      real payload, so delta ≈ 0 and this correctly returns False. Only a
      genuinely different response for the internal target vs. the
      documentation-only control — i.e. the server actually treating the
      two hosts differently — passes this gate.

    [P1-FIX] 2-dimension noise floor on composite_z path:
      Requires ≥ MIN_ANOMALOUS_DIMS dimensions to be |z| ≥ 1.5.
      A single-dimension spike (e.g. timing alone) gets TENTATIVE max.

    [P0-FIX] dns_failure only triggers on EXTERNAL (OOB/attacker-controlled)
      domain payloads, not on loopback or RFC1918 probes where DNS failure
      is expected behavior.
    """
    if result.control_composite_z is not None:
        delta = result.structural_z_raw - result.control_structural_z_raw
        if delta < DIFFERENTIAL_MARGIN:
            return False

    # Composite z-score path: require ≥2 anomalous dimensions
    if result.composite_z >= SUSPICIOUS_THRESHOLD:
        anomalous_dims = _count_anomalous_dims(result)
        if anomalous_dims >= MIN_ANOMALOUS_DIMS:
            return True
        # Single-dim spike: still suspicious but gets a reduction flag
        if candidate is not None and "single_dim_spike" not in candidate.confidence_reduction_flags:
            candidate.confidence_reduction_flags.append("single_dim_spike")
        return result.composite_z >= SUSPICIOUS_THRESHOLD * 1.5  # higher bar

    # Error-class path
    if result.error_class == "connection_refused":
        return True
    if result.error_class == "timeout":
        return True
    if result.error_class == "success_foreign":
        return True

    # [P0-FIX] dns_failure gate: only for external/OOB payloads
    if result.error_class == "dns_failure":
        if result.payload and not _INTERNAL_IP_RE.search(result.payload):
            return True
        return False  # expected behavior for loopback probes

    return False


def _count_anomalous_dims(result: ProbeResult) -> int:
    """Count how many dimensions show |z| ≥ 1.5."""
    return sum([
        abs(result.z_timing)         >= 1.5,
        abs(result.z_content_length) >= 1.5,
        result.z_status              >= 1.0,
        result.z_redirect            >= 1.0,
    ])


def _is_blocked(result: ProbeResult) -> bool:
    """
    Returns True if the probe looks blocked by a WAF rather than passing
    through to the backend. Signals: 403/429/406/501 status codes.
    """
    return result.status_code in (403, 406, 429, 501, 503) and result.error_class == "none"


def describe_signature(result: ProbeResult) -> str:
    """
    Human-readable explanation of WHY a result is suspicious.
    Embedded into Finding.observation for triage transparency.
    """
    shifts = []
    if abs(result.z_timing) >= 1.5:
        shifts.append(f"timing z={result.z_timing:.2f}")
    if result.z_redirect:
        shifts.append(f"redirect-depth Δ={result.z_redirect}")
    if result.z_status:
        shifts.append(f"status z={result.z_status:.2f}")
    if abs(result.z_content_length) >= 1.5:
        shifts.append(f"content-length z={result.z_content_length:.2f}")

    err = (
        f", error_class={result.error_class}"
        if result.error_class not in (None, "none")
        else ""
    )
    control = ""
    if result.control_composite_z is not None:
        delta = result.structural_z_raw - result.control_structural_z_raw
        control = (
            f", control_z={result.control_composite_z:.2f} (structural Δ={delta:.2f} "
            f"vs external decoy of matching shape, timing excluded)"
        )
    return (
        f"composite_z={result.composite_z:.2f} "
        f"({', '.join(shifts) or 'no single dimension dominant'})"
        f"{control}"
        f"{err}"
    )
