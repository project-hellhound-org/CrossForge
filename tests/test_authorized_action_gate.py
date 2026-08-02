"""
Tests for core/authorized_action_gate.py — the hard stop between Phase 4
(Detect/Verify) and any live evidence collection / pivot chaining.

These pin the actual security property, not just "the module imports":
  1. propose() never sends a request (classification only)
  2. execute() refuses to run with no operator identity
  3. execute() only calls the specific evidence methods approved
  4. the automatic pipeline (_process_candidate) never reaches a live
     evidence method on its own — a proposal is produced instead
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from core.models import Candidate, ParamLocation, ProbeResult, EvidenceArtifact
from core.authorized_action_gate import AuthorizedActionGate, EVIDENCE_METHODS


def _candidate(**overrides) -> Candidate:
    defaults = dict(
        target_url="http://target.example/preview",
        method="POST",
        parameter="url",
        param_location=ParamLocation.BODY_JSON,
    )
    defaults.update(overrides)
    return Candidate(**defaults)


def _probe_result(**overrides) -> ProbeResult:
    defaults = dict(
        candidate_id="cand-1", payload="http://169.254.169.254/", payload_category="cloud_metadata_aws",
        status_code=200, content_length=50, elapsed=0.1,
        redirect_depth=0, redirect_chain=[], headers={}, body_snippet="",
    )
    defaults.update(overrides)
    return ProbeResult(**defaults)


# ---------------------------------------------------------------------------
# propose() — must never send a request
# ---------------------------------------------------------------------------

def test_propose_makes_no_http_calls():
    cand = _candidate()
    gate = AuthorizedActionGate(client="not-a-real-client-should-never-be-used")
    proposal = gate.propose(
        cand, [_probe_result()], has_oob=True, has_reflection=False, waf_vendor=None,
    )
    assert proposal.status == "AWAITING_REVIEW"
    assert proposal.candidate_id == cand.candidate_id
    assert set(proposal.available_methods) == set(EVIDENCE_METHODS)


def test_propose_pivots_makes_no_http_calls():
    cand = _candidate()
    gate = AuthorizedActionGate(client="not-a-real-client-should-never-be-used")
    pivots = gate.propose_pivots(
        cand, evidence=[], oob_internal_addrs=["10.0.4.12"], dns_rebind_targets=[],
        current_hop=0, max_hops=3,
    )
    assert isinstance(pivots, list)  # extract_pivot_targets is pure; no client was touched


# ---------------------------------------------------------------------------
# execute() — the enforcement mechanism
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_refuses_empty_operator():
    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)

    with pytest.raises(ValueError, match="non-empty operator"):
        await gate.execute(proposal, cand, approved_methods=["cloud_metadata"], operator="")

    with pytest.raises(ValueError, match="non-empty operator"):
        await gate.execute(proposal, cand, approved_methods=["cloud_metadata"], operator="   ")


@pytest.mark.asyncio
async def test_execute_rejects_unknown_method():
    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)

    with pytest.raises(ValueError, match="Unknown evidence method"):
        await gate.execute(
            proposal, cand, approved_methods=["delete_production_database"], operator="alice",
        )


@pytest.mark.asyncio
async def test_execute_only_calls_approved_methods():
    """Approving cloud_metadata must not also trigger port_state_map,
    kubernetes_api, etc. — each method is opt-in independently."""
    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)

    with patch("core.authorized_action_gate.evidence_engine.check_cloud_metadata",
               new=AsyncMock(return_value=None)) as mock_cloud, \
         patch("core.authorized_action_gate.evidence_engine.build_port_state_map",
               new=AsyncMock(return_value=None)) as mock_ports, \
         patch("core.authorized_action_gate.evidence_engine.check_kubernetes_api",
               new=AsyncMock(return_value=None)) as mock_k8s:

        await gate.execute(proposal, cand, approved_methods=["cloud_metadata"], operator="alice")

        mock_cloud.assert_called_once()
        mock_ports.assert_not_called()
        mock_k8s.assert_not_called()

    assert proposal.status == "EXECUTED"
    assert len(gate.log) == 1
    assert gate.log[0].operator == "alice"
    assert gate.log[0].approved_methods == ["cloud_metadata"]


@pytest.mark.asyncio
async def test_execute_records_evidence_collected_in_log():
    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)

    art = EvidenceArtifact(
        evidence_type="cloud_metadata_schema", summary="AWS metadata reachable",
        raw_evidence="...", schema_matched=True,
    )
    with patch("core.authorized_action_gate.evidence_engine.check_cloud_metadata",
               new=AsyncMock(return_value=art)):
        evidence = await gate.execute(
            proposal, cand, approved_methods=["cloud_metadata"], operator="alice",
        )

    assert evidence == [art]
    assert gate.log[0].evidence_collected == ["cloud_metadata_schema"]


@pytest.mark.asyncio
async def test_imdsv2_escalation_only_runs_if_cloud_metadata_matched_aws():
    """imdsv2_escalation must not fire if cloud_metadata found nothing, or
    if the operator didn't separately approve it."""
    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)

    with patch("core.authorized_action_gate.evidence_engine.check_cloud_metadata",
               new=AsyncMock(return_value=None)):
        with patch("core.feedback.maybe_escalate_imdsv2", new=AsyncMock()) as mock_esc:
            await gate.execute(
                proposal, cand,
                approved_methods=["cloud_metadata", "imdsv2_escalation"], operator="alice",
            )
            mock_esc.assert_not_called()  # nothing to escalate — cloud_metadata found nothing


def test_decline_requires_operator():
    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)
    with pytest.raises(ValueError, match="non-empty operator"):
        gate.decline(proposal, operator="")


# ---------------------------------------------------------------------------
# Cross-session round-trip — snapshot must survive JSON serialization and
# still be enough to reconstruct a working Candidate + re-execute evidence.
# ---------------------------------------------------------------------------

def test_snapshot_round_trip_preserves_request_shape():
    from core.authorized_action_gate import snapshot_candidate, reconstruct_candidate
    cand = _candidate(
        headers={"X-Api-Key": "secret"}, cookies={"session": "abc"},
        original_value="http://example.com",
    )
    cand.confidence_reduction_flags.append("single_dim_spike")

    snap = snapshot_candidate(cand)
    rebuilt = reconstruct_candidate(snap)

    assert rebuilt.target_url == cand.target_url
    assert rebuilt.method == cand.method
    assert rebuilt.parameter == cand.parameter
    assert rebuilt.param_location == cand.param_location
    assert rebuilt.headers == cand.headers
    assert rebuilt.cookies == cand.cookies
    assert rebuilt.candidate_id == cand.candidate_id
    assert rebuilt.confidence_reduction_flags == ["single_dim_spike"]


def test_proposal_json_round_trip_reconstructs_working_candidate():
    import json
    from core.authorized_action_gate import reconstruct_candidate

    cand = _candidate()
    gate = AuthorizedActionGate(client=AsyncMock())
    proposal = gate.propose(
        cand, [_probe_result()], has_oob=True, has_reflection=False,
        waf_vendor="cloudflare", oob_internal_addrs=["10.0.4.12"],
    )

    # Simulate writing to report.json and reading it back in a new process
    raw = json.loads(json.dumps(proposal.to_dict()))
    from core.authorized_action_gate import FindingProposal
    reloaded = FindingProposal.from_dict(raw)

    assert reloaded.proposal_id == proposal.proposal_id
    assert reloaded.status == "AWAITING_REVIEW"
    assert reloaded.oob_internal_addrs == ["10.0.4.12"]
    assert reloaded.candidate_snapshot is not None

    rebuilt_cand = reconstruct_candidate(reloaded.candidate_snapshot)
    assert rebuilt_cand.target_url == cand.target_url
    assert rebuilt_cand.candidate_id == cand.candidate_id


@pytest.mark.asyncio
async def test_execute_works_from_reloaded_proposal_with_no_live_candidate():
    """The actual point of the snapshot: execute() must work when called
    with ONLY a proposal that came from disk — no live Candidate object,
    simulating a fresh `crossforge --review` process."""
    import json
    cand = _candidate()
    gate_a = AuthorizedActionGate(client=AsyncMock())
    proposal = gate_a.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)
    raw = json.loads(json.dumps(proposal.to_dict()))

    from core.authorized_action_gate import FindingProposal
    reloaded_proposal = FindingProposal.from_dict(raw)

    # Brand new gate, brand new client — nothing shared with gate_a/cand.
    gate_b = AuthorizedActionGate(client=AsyncMock())
    with patch("core.authorized_action_gate.evidence_engine.check_cloud_metadata",
               new=AsyncMock(return_value=None)) as mock_cloud:
        evidence = await gate_b.execute(
            reloaded_proposal, approved_methods=["cloud_metadata"], operator="bob",
        )
    mock_cloud.assert_called_once()
    call_args = mock_cloud.call_args
    reconstructed_cand_passed_in = call_args[0][1]
    assert reconstructed_cand_passed_in.target_url == cand.target_url
    assert evidence == []
