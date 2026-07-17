"""
HELLHOUND SSRF v5.0 - Phase 8: Confidence Scoring & Severity Tiering
=======================================================================
v5 additions:
  [v5-NEW] Known-exploits escalation — when Phase 6 port_state_map reveals
           open ports and Phase 8 cross-references them against the KnownExploit
           registry, severity is promoted to at least 'critical' for Docker
           daemon / K8s API / Redis RCE class services.
  [v5-NEW] Confidence-reduction flag awareness — candidates with
           confidence_reduction_flags get their tier capped one level below
           their evidence-based tier (e.g. infra_noise + TENTATIVE → INFO only).
  [v5-NEW] CVSS vector includes Known-exploit CVE reference in output dict.
"""

from __future__ import annotations
from core.models import (
    Candidate, ConfidenceTier, EvidenceArtifact, KnownExploit,
)

# CVSS 3.1 vectors per tier (AV:N AC:L baseline — adjust per engagement)
_CVSS_BY_TIER = {
    ConfidenceTier.TENTATIVE: {
        "vector":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "score":    4.3,
        "severity": "medium",
    },
    ConfidenceTier.FIRM: {
        "vector":   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
        "score":    6.5,
        "severity": "high",
    },
    ConfidenceTier.CERTAIN: {
        "vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "score":    8.6,
        "severity": "critical",
    },
    ConfidenceTier.CRITICAL_PLUS: {
        "vector":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",
        "score":    9.6,
        "severity": "critical",
    },
}

_CONFIDENCE_LABEL = {
    ConfidenceTier.TENTATIVE:     "low",
    ConfidenceTier.FIRM:          "medium",
    ConfidenceTier.CERTAIN:       "high",
    ConfidenceTier.CRITICAL_PLUS: "high",
}

# Reduction-flag → maximum allowed tier
_REDUCTION_CAP = {
    "infra_noise":      ConfidenceTier.TENTATIVE,
    "spa_catchall":     ConfidenceTier.FIRM,          # OOB can still be real
    "single_dim_spike": ConfidenceTier.TENTATIVE,
    "header_blocklisted": None,                        # None = skip finding entirely
}

_TIER_ORDER = [
    ConfidenceTier.TENTATIVE,
    ConfidenceTier.FIRM,
    ConfidenceTier.CERTAIN,
    ConfidenceTier.CRITICAL_PLUS,
]


def determine_tier(
    suspicious_results: list,
    has_oob: bool,
    evidence: list[EvidenceArtifact],
    chained: bool,
    candidate: Candidate | None = None,
    known_exploits: list[KnownExploit] | None = None,
) -> ConfidenceTier | None:
    """
    Top-down evaluation — strongest available signal wins, then
    confidence-reduction flags cap the result downward.

    Returns None if the candidate should be skipped entirely
    (e.g. header_blocklisted flag with no real evidence).
    """
    # ---- Raw tier from evidence ----------------------------------------
    if chained:
        raw_tier = ConfidenceTier.CRITICAL_PLUS
    elif any(e.schema_matched for e in evidence):
        raw_tier = ConfidenceTier.CERTAIN
    elif has_oob:
        raw_tier = ConfidenceTier.FIRM
    elif suspicious_results:
        raw_tier = ConfidenceTier.TENTATIVE
    else:
        return None

    # ---- [v5-NEW] Known-exploits escalation ----------------------------
    # If evidence contains a port_state_map with open ports that cross-
    # reference against a known-exploitable service, push to CRITICAL_PLUS.
    if known_exploits and raw_tier in (ConfidenceTier.CERTAIN, ConfidenceTier.FIRM):
        critical_exploits = [e for e in known_exploits if e.escalate_to == "critical"]
        if critical_exploits:
            raw_tier = ConfidenceTier.CRITICAL_PLUS

    # ---- [v5-NEW] K8s / Docker daemon special escalation ---------------
    for art in evidence:
        if art.evidence_type in ("kubernetes_api", "ecs_task_metadata"):
            raw_tier = ConfidenceTier.CRITICAL_PLUS
            break

    # ---- Confidence-reduction flag cap ---------------------------------
    if candidate and candidate.confidence_reduction_flags:
        for flag in candidate.confidence_reduction_flags:
            cap = _REDUCTION_CAP.get(flag)
            if cap is None:
                # None means "skip entirely" only if there's no OOB/evidence
                if raw_tier == ConfidenceTier.TENTATIVE:
                    return None
                continue
            cap_idx = _TIER_ORDER.index(cap)
            raw_idx = _TIER_ORDER.index(raw_tier)
            if raw_idx > cap_idx:
                raw_tier = _TIER_ORDER[cap_idx]

    return raw_tier


def score(
    tier: ConfidenceTier,
    known_exploits: list[KnownExploit] | None = None,
) -> dict:
    """
    Returns {cvss_vector, cvss_score, severity, confidence, exploit_refs}.
    """
    cvss = _CVSS_BY_TIER[tier]
    result = {
        "cvss_vector":  cvss["vector"],
        "cvss_score":   cvss["score"],
        "severity":     cvss["severity"],
        "confidence":   _CONFIDENCE_LABEL[tier],
        "exploit_refs": [],
    }

    # [v5-NEW] Embed known-exploit refs in the score output
    if known_exploits:
        result["exploit_refs"] = [
            {
                "service":      e.service,
                "port":         e.port,
                "cve":          e.cve,
                "cvss_score":   e.cvss_score,
                "exploit_type": e.exploit_type,
                "description":  e.description,
            }
            for e in known_exploits
        ]
        # Use the max CVSS score from known exploits if higher
        max_ke_cvss = max((e.cvss_score for e in known_exploits), default=0.0)
        if max_ke_cvss > result["cvss_score"]:
            result["cvss_score"] = max_ke_cvss

    return result
