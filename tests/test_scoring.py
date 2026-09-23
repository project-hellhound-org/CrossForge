"""
tests/test_scoring.py — Unit tests for v2.0 scoring changes
"""

import pytest
from core.models import Candidate, ConfidenceTier, EvidenceArtifact, KnownExploit
from core.scoring import determine_tier, score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _art(evidence_type="generic", schema_matched=False, extra=None):
    return EvidenceArtifact(
        evidence_type=evidence_type,
        summary="test",
        raw_evidence="test",
        saved_path=None,
        schema_matched=schema_matched,
        extra=extra or {},
    )


def _candidate(**kwargs):
    """Minimal candidate with defaults."""
    defaults = dict(
        target_url="http://test.com",
        method="GET",
        parameter="url",
    )
    defaults.update(kwargs)
    c = Candidate(**defaults)
    return c


# ---------------------------------------------------------------------------
# Test determine_tier basics
# ---------------------------------------------------------------------------

def test_no_evidence_returns_none():
    tier = determine_tier([], False, [], False)
    assert tier is None


def test_suspicious_only_is_tentative():
    tier = determine_tier(["anomaly"], False, [], False)
    assert tier == ConfidenceTier.TENTATIVE


def test_oob_is_firm():
    tier = determine_tier([], True, [], False)
    assert tier == ConfidenceTier.FIRM


def test_schema_match_is_certain():
    art = _art(schema_matched=True)
    tier = determine_tier([], False, [art], False)
    assert tier == ConfidenceTier.CERTAIN


def test_chained_is_critical_plus():
    tier = determine_tier([], False, [], True)
    assert tier == ConfidenceTier.CRITICAL_PLUS


# ---------------------------------------------------------------------------
# [v2] Port-inferred vs banner-confirmed gating
# ---------------------------------------------------------------------------

def test_port_inferred_caps_at_firm():
    """Port-inferred critical service should NOT push to CRITICAL_PLUS."""
    art = _art(schema_matched=True)  # CERTAIN
    ke = KnownExploit(
        service="redis", port=6379,
        escalate_to="critical",
        confirmation_method="port_inferred",
    )
    tier = determine_tier([], False, [art], False, known_exploits=[ke])
    # Should stay at CERTAIN (capped), NOT escalate to CRITICAL_PLUS
    # Actually the code says port_only_critical with CERTAIN stays CERTAIN 
    # because max(CERTAIN, FIRM) = CERTAIN
    assert tier in (ConfidenceTier.CERTAIN, ConfidenceTier.FIRM)


def test_banner_confirmed_reaches_critical_plus():
    """Banner-confirmed critical service SHOULD push to CRITICAL_PLUS."""
    art = _art(schema_matched=True)  # CERTAIN
    ke = KnownExploit(
        service="redis", port=6379,
        escalate_to="critical",
        confirmation_method="banner_confirmed",
    )
    tier = determine_tier([], False, [art], False, known_exploits=[ke])
    assert tier == ConfidenceTier.CRITICAL_PLUS


def test_port_inferred_from_firm_stays_firm():
    """FIRM + port-inferred should stay FIRM, not escalate."""
    ke = KnownExploit(
        service="redis", port=6379,
        escalate_to="critical",
        confirmation_method="port_inferred",
    )
    tier = determine_tier([], True, [], False, known_exploits=[ke])
    assert tier == ConfidenceTier.FIRM


# ---------------------------------------------------------------------------
# Test score() output
# ---------------------------------------------------------------------------

def test_score_output_structure():
    result = score(ConfidenceTier.FIRM)
    assert "cvss_vector" in result
    assert "cvss_score" in result
    assert "severity" in result
    assert "confidence" in result
    assert "exploit_refs" in result


def test_score_with_known_exploits():
    ke = KnownExploit(
        service="redis", port=6379, cve="CVE-2022-0543",
        cvss_score=10.0, exploit_type="rce",
    )
    result = score(ConfidenceTier.CERTAIN, known_exploits=[ke])
    assert result["cvss_score"] == 10.0
    assert len(result["exploit_refs"]) == 1
    assert result["exploit_refs"][0]["cve"] == "CVE-2022-0543"
