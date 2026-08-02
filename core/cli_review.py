"""
core/cli_review.py

Backs `crossforge --review <report.json>` — the practical missing piece
identified alongside the AuthorizedActionGate: a gate that's correct but
only callable from a Python REPL isn't usable by an operator. This module
is the thin interactive layer; all the actual enforcement (operator
identity required, per-method opt-in, no live request until approved)
lives in core/authorized_action_gate.py and is unchanged by anything here.

Design point worth being explicit about: this is a SEPARATE process from
the one that ran the scan. There is no live Candidate object, no
in-memory engagement state — everything needed to act on a proposal comes
from what got written into the report's JSON (see
CandidateSnapshot/FindingProposal.to_dict() in authorized_action_gate.py).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from core.models import Finding, ScanReport
from core.authorized_action_gate import (
    AuthorizedActionRecord, EVIDENCE_METHODS, FindingProposal,
)
from core.console import C, color, tprint, section, info, warn, err, ok, dim


# ---------------------------------------------------------------------------
# Report load / save
# ---------------------------------------------------------------------------

def load_report(path: Path) -> ScanReport:
    """
    Reconstructs a ScanReport from a JSON file written by
    reporter.write_json_report(). Finding/FindingProposal/
    AuthorizedActionRecord are all plain dataclasses whose to_dict()
    output matches their constructor's field names exactly, so
    reconstruction is direct — no separate schema to keep in sync.
    """
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    data = json.loads(path.read_text())

    findings = [Finding(**f) for f in data.get("findings", [])]
    proposals = [FindingProposal.from_dict(p) for p in data.get("pending_proposals", [])]
    action_log = [AuthorizedActionRecord(**r) for r in data.get("authorized_action_log", [])]

    report = ScanReport(
        status=data.get("status", "complete"),
        errors=list(data.get("errors", [])),
        gap_reason=data.get("gap_reason"),
        findings=findings,
        skipped_candidates=list(data.get("skipped_candidates", [])),
        pending_proposals=proposals,
        authorized_action_log=action_log,
    )
    return report


def save_report(report: ScanReport, path: Path) -> None:
    """Writes the report back to the SAME path it was loaded from, after
    a review decision. Called after every single decision (not batched at
    the end) so an operator quitting partway through a review session
    doesn't lose already-made decisions — see run_review_session()."""
    from core import reporter
    reporter.write_json_report(report, path)
    sarif_path = path.with_suffix(".sarif")
    try:
        reporter.write_sarif_report(report, sarif_path)
    except Exception:
        # SARIF regeneration failing shouldn't block saving the JSON
        # report, which is the source of truth this CLI reads from.
        pass


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _print_proposal_row(idx: int, p: FindingProposal) -> None:
    sig = p.signal_summary
    badges = []
    if sig.get("has_oob"):
        badges.append(color("OOB", C.BGREEN, C.BOLD))
    if sig.get("has_reflection"):
        badges.append(color("REFLECT", C.BCYAN))
    if sig.get("waf_vendor"):
        badges.append(color(f"WAF:{sig['waf_vendor']}", C.BYELLOW))
    badge_str = " ".join(badges) if badges else color("no signal badges", C.DIM)

    tprint(f"  {color(f'[{idx}]', C.BWHITE, C.BOLD)} {color(p.proposal_id, C.BCYAN)}  "
           f"({p.protocol_classification})  {badge_str}")
    tprint(f"      {p.parameter} @ {p.target_url}")
    tprint(f"      {color('z=' + str(round(sig.get('top_composite_z', 0), 2)), C.DIM)}  "
           f"status={color(p.status, C.BYELLOW if p.status == 'AWAITING_REVIEW' else C.DIM)}")


def _print_methods_menu() -> None:
    tprint(f"\n  {color('Available evidence methods:', C.BWHITE, C.BOLD)}")
    for i, (name, m) in enumerate(sorted(EVIDENCE_METHODS.items()), start=1):
        tprint(f"    {color(str(i), C.BCYAN)}. {color(name, C.BWHITE)} — {m.description}")
        tprint(f"       {color('risk:', C.DIM)} {color(m.risk_note, C.DIM)}")


# ---------------------------------------------------------------------------
# Interactive session
# ---------------------------------------------------------------------------

def _prompt(msg: str) -> str:
    try:
        return input(msg).strip()
    except EOFError:
        return "q"


async def run_review_session(report_path: Path, config_path: Path) -> None:
    """
    The interactive loop behind `crossforge --review`. Never calls
    AuthorizedActionGate.execute() itself — delegates every execution to
    CrossForgeAgent.run_authorized_evidence(), so this file adds no new
    path into evidence_engine.py. Its only job is turning operator input
    into the (proposal_id, approved_methods, operator) arguments that
    method already requires.
    """
    from core.agent import CrossForgeAgent  # deferred: avoid import cost on every CLI invocation

    report = load_report(report_path)
    pending = [p for p in report.pending_proposals if p.status == "AWAITING_REVIEW"]

    section("AUTHORIZED ACTION REVIEW")
    if not pending:
        ok(f"No pending proposals awaiting review in {report_path}")
        if report.pending_proposals:
            dim(f"({len(report.pending_proposals)} proposal(s) already decided — "
                f"see authorized_action_log)")
        return

    info(f"{len(pending)} finding(s) awaiting operator review")
    tprint("")
    for i, p in enumerate(pending, start=1):
        _print_proposal_row(i, p)
        tprint("")

    agent = CrossForgeAgent(config_path)

    while True:
        pending = [p for p in report.pending_proposals if p.status == "AWAITING_REVIEW"]
        if not pending:
            ok("All proposals decided.")
            break

        sel = _prompt(
            f"\n{color('Select proposal', C.BWHITE, C.BOLD)} "
            f"[1-{len(pending)}, 'l' to list, 'q' to quit]: "
        )
        if sel.lower() in ("q", "quit", ""):
            break
        if sel.lower() in ("l", "list"):
            for i, p in enumerate(pending, start=1):
                _print_proposal_row(i, p)
            continue
        if not sel.isdigit() or not (1 <= int(sel) <= len(pending)):
            warn(f"'{sel}' isn't a valid selection.")
            continue

        proposal = pending[int(sel) - 1]
        _print_proposal_row(int(sel), proposal)
        _print_methods_menu()

        methods_in = _prompt(
            f"\n{color('Approve methods', C.BWHITE, C.BOLD)} "
            f"(comma-separated names, 'all', or 'skip' to decline): "
        )
        if methods_in.lower() in ("skip", "decline", "d"):
            reason = _prompt("Decline reason (optional): ")
            operator = _prompt(f"{color('Operator identity', C.BWHITE, C.BOLD)} (required): ")
            if not operator.strip():
                warn("Operator identity is required — decline not recorded.")
                continue
            agent._gate.decline(proposal, operator=operator, reason=reason)
            report.authorized_action_log = list(agent._gate.log)
            save_report(report, report_path)
            ok(f"Declined {proposal.proposal_id}.")
            continue

        if methods_in.lower() == "all":
            approved = sorted(EVIDENCE_METHODS)
        else:
            approved = [m.strip() for m in methods_in.split(",") if m.strip()]
        unknown = set(approved) - set(EVIDENCE_METHODS)
        if unknown:
            warn(f"Unknown method(s), ignoring selection: {sorted(unknown)}")
            continue

        operator = _prompt(f"{color('Operator identity', C.BWHITE, C.BOLD)} (required): ")
        if not operator.strip():
            warn("Operator identity is required — no evidence collection performed.")
            continue

        confirm = _prompt(
            f"About to run {color(', '.join(approved), C.BYELLOW)} against "
            f"{color(proposal.target_url, C.BCYAN)} as operator "
            f"'{operator}'. Confirm? [y/N]: "
        )
        if confirm.lower() not in ("y", "yes"):
            info("Not executed.")
            continue

        try:
            finding = await agent.run_authorized_evidence(
                report, proposal.proposal_id,
                approved_methods=approved, operator=operator,
            )
        except ValueError as exc:
            err(str(exc))
            continue

        report.authorized_action_log = list(agent._gate.log)
        save_report(report, report_path)
        ok(f"Executed. Finding tier: "
           f"{color(getattr(finding, 'confidence_tier', finding.confidence), C.BRED, C.BOLD)}")
        ae = finding.details.get("authorized_evidence", {})
        if ae.get("evidence_types"):
            dim(f"Evidence collected: {', '.join(ae['evidence_types'])}")
        else:
            dim("No evidence matched (methods ran, nothing confirmed).")

    tprint(f"\n{color('Report updated:', C.DIM)} {report_path}")
