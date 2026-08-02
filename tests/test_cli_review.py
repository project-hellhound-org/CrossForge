"""
Tests for core/cli_review.py — specifically the load_report()/save_report()
round-trip, since that's where a field-name mismatch between to_dict() and
the dataclass constructor would silently corrupt a report rather than
raise (or would raise a TypeError, which these tests would catch).

The interactive loop itself (run_review_session) is exercised at the
mechanism level via the AuthorizedActionGate tests in
test_authorized_action_gate.py — it's a thin wrapper around
agent.run_authorized_evidence(), which is already covered there and via
the reconstruction tests below.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.models import Candidate, ParamLocation, ScanReport
from core.authorized_action_gate import AuthorizedActionGate
from core.cli_review import load_report, save_report


def _candidate() -> Candidate:
    return Candidate(
        target_url="http://target.example/preview",
        method="POST", parameter="url", param_location=ParamLocation.BODY_JSON,
    )


def test_load_report_round_trips_empty_report(tmp_path):
    report = ScanReport(status="complete")
    path = tmp_path / "report.json"
    save_report(report, path)

    loaded = load_report(path)
    assert loaded.status == "complete"
    assert loaded.findings == []
    assert loaded.pending_proposals == []
    assert loaded.authorized_action_log == []


def test_load_report_round_trips_pending_proposal(tmp_path):
    cand = _candidate()
    gate = AuthorizedActionGate(client=None)
    proposal = gate.propose(
        cand, [], has_oob=True, has_reflection=False, waf_vendor="cloudflare",
        oob_internal_addrs=["10.0.4.12"],
    )
    report = ScanReport(status="complete")
    report.pending_proposals.append(proposal)

    path = tmp_path / "report.json"
    save_report(report, path)

    loaded = load_report(path)
    assert len(loaded.pending_proposals) == 1
    lp = loaded.pending_proposals[0]
    assert lp.proposal_id == proposal.proposal_id
    assert lp.status == "AWAITING_REVIEW"
    assert lp.signal_summary["waf_vendor"] == "cloudflare"
    assert lp.oob_internal_addrs == ["10.0.4.12"]
    # The whole point of the snapshot — must survive the JSON round-trip
    # intact enough to reconstruct a working Candidate later.
    assert lp.candidate_snapshot is not None
    assert lp.candidate_snapshot.target_url == cand.target_url
    assert lp.candidate_snapshot.parameter == cand.parameter


def test_save_report_is_idempotent_and_readable_by_json(tmp_path):
    """Sanity check that the file on disk is valid, re-parseable JSON —
    catches accidental non-serializable objects (e.g. an Enum leaking
    through instead of its .value) that asdict()/default=str would
    otherwise silently stringify into something load_report can't use."""
    cand = _candidate()
    gate = AuthorizedActionGate(client=None)
    proposal = gate.propose(cand, [], has_oob=False, has_reflection=True, waf_vendor=None)
    report = ScanReport(status="complete")
    report.pending_proposals.append(proposal)

    path = tmp_path / "report.json"
    save_report(report, path)
    raw = json.loads(path.read_text())  # must not raise
    assert raw["pending_proposals"][0]["candidate_snapshot"]["param_location"] == "body_json"

    # Round-trip a second time to confirm nothing degrades on re-save
    loaded = load_report(path)
    save_report(loaded, path)
    reloaded = load_report(path)
    assert reloaded.pending_proposals[0].proposal_id == proposal.proposal_id


# ---------------------------------------------------------------------------
# run_review_session — decline path (no network required; catches the
# "decision enforced correctly but never synced into the saved report"
# class of bug found via manual smoke test during development)
# ---------------------------------------------------------------------------

import pytest


@pytest.mark.asyncio
async def test_review_session_decline_persists_to_action_log(tmp_path, monkeypatch):
    from core.cli_review import run_review_session

    cand = _candidate()
    gate = AuthorizedActionGate(client=None)
    proposal = gate.propose(cand, [], has_oob=True, has_reflection=False, waf_vendor=None)
    report = ScanReport(status="complete")
    report.pending_proposals.append(proposal)

    report_path = tmp_path / "report.json"
    save_report(report, report_path)

    # Scripted operator input: select [1], decline, no reason, operator name, quit.
    responses = iter(["1", "skip", "smoke-test reason", "operator-bob", "q"])
    monkeypatch.setattr("builtins.input", lambda *_: next(responses))

    config_path = Path(__file__).parent.parent / "core" / "config.yaml"
    await run_review_session(report_path, config_path)

    reloaded = load_report(report_path)
    assert reloaded.pending_proposals[0].status == "DECLINED"
    # This is the exact assertion that would have caught the bug: status
    # updated in memory but authorized_action_log left empty on disk.
    assert len(reloaded.authorized_action_log) == 1
    assert reloaded.authorized_action_log[0].operator == "operator-bob"
    assert reloaded.authorized_action_log[0].action == "declined"
    assert reloaded.authorized_action_log[0].reason == "smoke-test reason"
