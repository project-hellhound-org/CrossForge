"""
core/authorized_action_gate.py

Implements the AuthorizedActionGate from CrossForge_Blueprint_Scoped.md,
Section 1.4 — the hard stop between Phase 4 (Detect/Verify) and any action
that touches, fingerprints, or extracts data from an internal service.

WHY THIS MODULE EXISTS (audit findings this replaces — verified against
the actual code, not assumed):

  - core/agent.py's _process_candidate() previously called
    check_cloud_metadata, check_kubernetes_api, check_ecs_metadata,
    check_oracle_cloud, build_port_state_map, fingerprint_internal_service,
    check_file_read, check_crlf_injection, and feedback.maybe_escalate_imdsv2
    UNCONDITIONALLY whenever a heuristic predicate (_warrants_evidence)
    returned True. No operator was ever consulted.

  - feedback.maybe_escalate_imdsv2 actively defeats AWS's IMDSv2
    anti-SSRF token protection: it requests a session token, then uses
    that token to re-probe metadata. This is a live control bypass, not
    a passive check.

  - evidence_engine.build_port_state_map performs a real internal port
    scan (COMMON_INTERNAL_PORTS) through the SSRF sink.

  - config.yaml's `evidence.aggressive` flag — documented as gating
    build_port_state_map and protocol-banner probing, defaulting to
    false — is never read anywhere in the codebase (confirmed by a
    full-repo grep: it appears only in config.yaml itself and nowhere
    else). It is dead configuration. Every scan has been running full
    evidence collection regardless of this flag's value. A prior
    completion report's claim that this was fixed ("Aggressive evidence
    collection now requires explicit operator opt-in — Done") does not
    hold against the actual code.

  - core/chaining.py's extract_pivot_targets() feeds core/agent.py's
    pivot_queue, which is then consumed by a `while pivot_queue and hop
    < self._max_hops` loop (default max_hops=3) — automatically
    re-queuing newly discovered internal hosts as fresh candidates and
    re-running the full pipeline against them, with no operator
    checkpoint between hops. extract_pivot_targets() itself makes no
    requests (pure function over already-collected evidence/signals);
    the automatic re-queuing is what's ungated.

None of the functions in EVIDENCE_METHODS below have been changed. This
module does not touch evidence_engine.py or feedback.py — it changes who
is allowed to call them and when.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.models import Candidate, ContextClass, EvidenceArtifact, ParamLocation, ProbeResult
from core.http_client import HttpClient
from core import evidence_engine
from core.chaining import extract_pivot_targets, PivotTarget


# ---------------------------------------------------------------------------
# Candidate snapshot — makes a FindingProposal self-sufficient across
# process boundaries. A proposal generated during `crossforge --input ...`
# needs to be reviewable later by `crossforge --review report.json` in a
# SEPARATE process, where the original in-memory Candidate object no
# longer exists. Rather than requiring the reviewer to still have access
# to the scanning process (impossible in practice — an operator reviews
# findings after the scan, often the next day), the proposal carries
# everything HttpClient._inject() and the evidence_engine functions
# actually read off a Candidate (verified by grepping every
# `candidate.<attr>` access in evidence_engine.py and feedback.py — see
# CandidateSnapshot fields below), so a working Candidate can be rebuilt
# from JSON alone.
# ---------------------------------------------------------------------------

@dataclass
class CandidateSnapshot:
    candidate_id:             str
    target_url:                str
    method:                    str
    parameter:                 str
    param_location:            str    # ParamLocation.value
    headers:                    dict
    cookies:                    dict
    body_template:              "dict | None"
    baseline_query_context:     dict
    context_class:               str    # ContextClass.value — read by check_crlf_injection/check_host_header_ssrf
    confidence_reduction_flags: list
    spa_catchall:                bool

    def to_dict(self) -> dict:
        return {
            "candidate_id":              self.candidate_id,
            "target_url":                self.target_url,
            "method":                    self.method,
            "parameter":                 self.parameter,
            "param_location":            self.param_location,
            "headers":                    self.headers,
            "cookies":                    self.cookies,
            "body_template":              self.body_template,
            "baseline_query_context":     self.baseline_query_context,
            "context_class":              self.context_class,
            "confidence_reduction_flags": self.confidence_reduction_flags,
            "spa_catchall":               self.spa_catchall,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CandidateSnapshot":
        return cls(
            candidate_id=d["candidate_id"], target_url=d["target_url"],
            method=d["method"], parameter=d["parameter"],
            param_location=d["param_location"], headers=dict(d.get("headers") or {}),
            cookies=dict(d.get("cookies") or {}), body_template=d.get("body_template"),
            baseline_query_context=dict(d.get("baseline_query_context") or {}),
            context_class=d.get("context_class", "unknown"),
            confidence_reduction_flags=list(d.get("confidence_reduction_flags") or []),
            spa_catchall=bool(d.get("spa_catchall", False)),
        )


def snapshot_candidate(cand: Candidate) -> CandidateSnapshot:
    """Pure extraction — reads, does not send anything."""
    return CandidateSnapshot(
        candidate_id=cand.candidate_id, target_url=cand.target_url,
        method=cand.method, parameter=cand.parameter,
        param_location=cand.param_location.value,
        headers=dict(cand.headers), cookies=dict(cand.cookies),
        body_template=cand.body_template,
        baseline_query_context=dict(cand.baseline_query_context or {}),
        context_class=cand.context_class.value,
        confidence_reduction_flags=list(cand.confidence_reduction_flags),
        spa_catchall=cand.spa_catchall,
    )


def reconstruct_candidate(snapshot: CandidateSnapshot) -> Candidate:
    """
    Rebuilds a Candidate object sufficient for evidence_engine functions
    and HttpClient.send() to operate on correctly. Deliberately minimal —
    fields not read by any evidence-collection code path (pre_score,
    payload_subset, baseline stats, etc.) are left at their dataclass
    defaults, since evidence collection never touches them (confirmed by
    grep — see this module's top-of-file note).
    """
    cand = Candidate(
        target_url=snapshot.target_url,
        method=snapshot.method,
        parameter=snapshot.parameter,
        param_location=ParamLocation(snapshot.param_location),
        headers=dict(snapshot.headers),
        cookies=dict(snapshot.cookies),
        body_template=snapshot.body_template,
    )
    cand.candidate_id = snapshot.candidate_id
    cand.baseline_query_context = dict(snapshot.baseline_query_context)
    cand.context_class = ContextClass(snapshot.context_class)
    cand.confidence_reduction_flags = list(snapshot.confidence_reduction_flags)
    cand.spa_catchall = snapshot.spa_catchall
    return cand


# ---------------------------------------------------------------------------
# Evidence method registry — every live, internal-service-touching action
# the agent is capable of, with a plain description of what it actually
# does on the wire. This is what an operator-facing review would render
# as a checkbox list. Nothing here executes until
# AuthorizedActionGate.execute() is called with an explicit operator
# identity and an explicit method list — see that method's docstring.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceMethod:
    name:        str
    description: str
    risk_note:   str


EVIDENCE_METHODS: dict[str, EvidenceMethod] = {
    "cloud_metadata": EvidenceMethod(
        "cloud_metadata",
        "Probe AWS/GCP/Azure/DigitalOcean/Oracle/Alibaba metadata "
        "endpoints for confirming schema markers.",
        "Live request to the target's real cloud metadata service if one "
        "exists — the AWS probe list includes the IAM "
        "security-credentials LIST path (reveals the attached role name; "
        "does not by itself fetch full temporary keys).",
    ),
    "imdsv2_escalation": EvidenceMethod(
        "imdsv2_escalation",
        "If cloud_metadata confirmed AWS: request an IMDSv2 session "
        "token and re-probe metadata using it.",
        "Actively bypasses AWS's IMDSv2 anti-SSRF token protection — a "
        "real security-control defeat, not a passive check. Requires "
        "cloud_metadata to have been approved and to have matched AWS.",
    ),
    "kubernetes_api": EvidenceMethod(
        "kubernetes_api",
        "Probe well-known in-cluster Kubernetes API server addresses.",
        "Live request to a real k8s API server if reachable.",
    ),
    "ecs_metadata": EvidenceMethod(
        "ecs_metadata",
        "Probe AWS ECS Task Metadata Service endpoints.",
        "Live request to a real ECS task metadata service if reachable.",
    ),
    "oracle_cloud": EvidenceMethod(
        "oracle_cloud",
        "Probe Oracle Cloud IMDS endpoints.",
        "Live request to a real OCI metadata service if reachable.",
    ),
    "port_state_map": EvidenceMethod(
        "port_state_map",
        "Port-scan COMMON_INTERNAL_PORTS on a target host through the "
        "SSRF sink.",
        "Active internal port scan — real traffic to every port probed, "
        "routed through the vulnerable application. This is the method "
        "config.yaml's (currently non-functional) evidence.aggressive "
        "flag was meant to gate.",
    ),
    "internal_service_fingerprint": EvidenceMethod(
        "internal_service_fingerprint",
        "Fingerprint a specific internal host (protocol banner grab).",
        "Active connection + banner read against a specific internal "
        "service address discovered via an OOB callback.",
    ),
    "file_read": EvidenceMethod(
        "file_read",
        "Confirm file:// local file read via /etc/hostname and "
        "/etc/os-release only.",
        "Reads two fixed, low-sensitivity files — narrowest-scope method "
        "in this registry.",
    ),
    "crlf_injection": EvidenceMethod(
        "crlf_injection",
        "Confirm CRLF/header injection via a reflected marker header.",
        "Single request with an injected header value.",
    ),
    "host_header_ssrf": EvidenceMethod(
        "host_header_ssrf",
        "Confirm routing-header-based SSRF (e.g. X-Forwarded-Host).",
        "Single request with a modified routing header.",
    ),
}


@dataclass
class FindingProposal:
    """
    What Phase 4 (Detect/Verify) hands to an operator once a candidate
    clears the has_signal gate. This is the ONLY thing produced
    automatically for a signal-positive candidate — no evidence method
    has run, no pivot has been queued. `available_methods` is the
    checkbox list; nothing in it has been executed yet.

    `candidate_snapshot` makes this self-sufficient across a process
    boundary — see CandidateSnapshot's docstring. A proposal loaded from
    a JSON report file by `crossforge --review` needs nothing else to be
    actionable.
    """
    proposal_id:             str
    candidate_id:            str
    target_url:              str
    parameter:               str
    protocol_classification: str    # e.g. "loopback_or_internal", "external_oob", "unclassified"
    signal_summary:          dict   # composite_z, has_oob, has_reflection, waf_vendor
    candidate_snapshot:       "CandidateSnapshot | None" = None
    oob_internal_addrs:      list[str] = field(default_factory=list)
    available_methods:       list[str] = field(default_factory=lambda: sorted(EVIDENCE_METHODS))
    status:                  str = "AWAITING_REVIEW"
    created_at:              str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "proposal_id":             self.proposal_id,
            "candidate_id":            self.candidate_id,
            "target_url":              self.target_url,
            "parameter":               self.parameter,
            "protocol_classification": self.protocol_classification,
            "signal_summary":          self.signal_summary,
            "candidate_snapshot":      self.candidate_snapshot.to_dict() if self.candidate_snapshot else None,
            "oob_internal_addrs":      self.oob_internal_addrs,
            "available_methods":       self.available_methods,
            "status":                  self.status,
            "created_at":              self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FindingProposal":
        snap = d.get("candidate_snapshot")
        return cls(
            proposal_id=d["proposal_id"], candidate_id=d["candidate_id"],
            target_url=d["target_url"], parameter=d["parameter"],
            protocol_classification=d["protocol_classification"],
            signal_summary=dict(d.get("signal_summary") or {}),
            candidate_snapshot=CandidateSnapshot.from_dict(snap) if snap else None,
            oob_internal_addrs=list(d.get("oob_internal_addrs") or []),
            available_methods=list(d.get("available_methods") or sorted(EVIDENCE_METHODS)),
            status=d.get("status", "AWAITING_REVIEW"),
            created_at=d.get("created_at", ""),
        )


@dataclass
class AuthorizedActionRecord:
    """One logged operator decision for a proposal — approve-and-execute
    or decline. Populated only by execute()/decline(), never by the
    automatic pipeline. `report.authorized_action_log` stays empty unless
    an operator actually went through this gate — see blueprint checklist."""
    proposal_id:        str
    operator:            str
    action:              str   # "executed" | "declined" | "pivots_approved"
    approved_methods:    list[str]
    evidence_collected:  list[str]   # evidence_type strings, not full artifacts
    reason:              str = ""
    decided_at:          str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AuthorizedActionGate:
    """
    The hard stop between Phase 4 (Detect/Verify) and Phase 5+ (anything
    that touches an internal service). See this module's docstring for
    the audit findings that necessitated it.
    """

    def __init__(self, client: HttpClient):
        self._client = client
        self.log: list[AuthorizedActionRecord] = []
        self._counter = 0

    # ------------------------------------------------------------------
    # Proposal (automatic, safe — classification only, zero requests)
    # ------------------------------------------------------------------

    def propose(
        self, cand: Candidate, suspicious: list[ProbeResult], *,
        has_oob: bool, has_reflection: bool, waf_vendor: "str | None",
        oob_internal_addrs: "list[str] | None" = None,
    ) -> FindingProposal:
        """Pure classification — no request is sent. This is what used to
        be the entry to _warrants_evidence()-gated live evidence
        collection; it now only produces the proposal object."""
        self._counter += 1
        protocol = (
            "external_oob" if has_oob else
            "differential_anomaly" if suspicious else
            "reflection_only"
        )
        return FindingProposal(
            proposal_id=f"{cand.candidate_id[:8]}-{self._counter}",
            candidate_id=cand.candidate_id,
            target_url=cand.target_url,
            parameter=cand.parameter,
            protocol_classification=protocol,
            signal_summary={
                "has_oob":            has_oob,
                "has_reflection":     has_reflection,
                "waf_vendor":         waf_vendor,
                "anomalous_results":  len(suspicious),
                "top_composite_z":    max((r.composite_z for r in suspicious), default=0.0),
            },
            candidate_snapshot=snapshot_candidate(cand),
            oob_internal_addrs=list(oob_internal_addrs or []),
        )

    def propose_pivots(
        self, cand: Candidate, evidence: list[EvidenceArtifact],
        oob_internal_addrs: list[str], dns_rebind_targets: list[str],
        *, current_hop: int, max_hops: int,
    ) -> list[PivotTarget]:
        """
        Classification only — extract_pivot_targets() makes no requests,
        it just derives candidate pivot hosts from signals/evidence
        already collected. Returned pivots are SUGGESTIONS; they are not
        added to any execution queue until approve_pivots() is called
        with an operator identity.
        """
        return extract_pivot_targets(
            cand, evidence, oob_internal_addrs, dns_rebind_targets,
            current_hop=current_hop, max_hops=max_hops,
        )

    # ------------------------------------------------------------------
    # Execution (gated — requires an explicit operator identity)
    # ------------------------------------------------------------------

    async def execute(
        self, proposal: FindingProposal, cand: "Candidate | None" = None, *,
        approved_methods: list[str], operator: str,
        internal_addrs: "list[str] | None" = None,
    ) -> list[EvidenceArtifact]:
        """
        The only place in the codebase permitted to call a live
        evidence-collection method after this gate was introduced.
        Requires a non-empty `operator` string — this is the enforcement
        mechanism matching the blueprint checklist item: "No code path
        calls [a live evidence method] without an operator field
        populated on the AuthorizedActionGate record."

        `cand`: pass the live Candidate object if you have one (e.g. the
        same process that generated the proposal). If omitted, it's
        rebuilt from proposal.candidate_snapshot — this is what makes
        cross-session review (`crossforge --review report.json`, a
        separate process) work without needing the original in-memory
        engagement state.
        """
        if cand is None:
            if proposal.candidate_snapshot is None:
                raise ValueError(
                    "No live Candidate provided and this proposal has no "
                    "candidate_snapshot to reconstruct one from — it may "
                    "predate the snapshot feature."
                )
            cand = reconstruct_candidate(proposal.candidate_snapshot)

        if not operator or not operator.strip():
            raise ValueError(
                "AuthorizedActionGate.execute() requires a non-empty operator "
                "identity — anonymous/automatic invocation is exactly what "
                "this gate exists to prevent."
            )
        unknown = set(approved_methods) - set(EVIDENCE_METHODS)
        if unknown:
            raise ValueError(f"Unknown evidence method(s): {sorted(unknown)}")

        evidence: list[EvidenceArtifact] = []
        ran: list[str] = []

        if "cloud_metadata" in approved_methods:
            art = await evidence_engine.check_cloud_metadata(self._client, cand)
            if art:
                evidence.append(art); ran.append("cloud_metadata")
                if "imdsv2_escalation" in approved_methods:
                    from core import feedback
                    esc = await feedback.maybe_escalate_imdsv2(self._client, cand, art)
                    if esc:
                        evidence.append(esc); ran.append("imdsv2_escalation")

        if "kubernetes_api" in approved_methods:
            art = await evidence_engine.check_kubernetes_api(self._client, cand)
            if art:
                evidence.append(art); ran.append("kubernetes_api")

        if "ecs_metadata" in approved_methods:
            art = await evidence_engine.check_ecs_metadata(self._client, cand)
            if art:
                evidence.append(art); ran.append("ecs_metadata")

        if "oracle_cloud" in approved_methods:
            art = await evidence_engine.check_oracle_cloud(self._client, cand)
            if art:
                evidence.append(art); ran.append("oracle_cloud")

        if "port_state_map" in approved_methods:
            art = await evidence_engine.build_port_state_map(self._client, cand, "127.0.0.1")
            if art:
                evidence.append(art); ran.append("port_state_map")

        if "internal_service_fingerprint" in approved_methods:
            for addr in (internal_addrs or []):
                art = await evidence_engine.fingerprint_internal_service(self._client, cand, addr)
                if art:
                    evidence.append(art); ran.append("internal_service_fingerprint")

        if "file_read" in approved_methods:
            art = await evidence_engine.check_file_read(self._client, cand)
            if art:
                evidence.append(art); ran.append("file_read")

        if "crlf_injection" in approved_methods:
            art = await evidence_engine.check_crlf_injection(self._client, cand)
            if art:
                evidence.append(art); ran.append("crlf_injection")

        if "host_header_ssrf" in approved_methods:
            art = await evidence_engine.check_host_header_ssrf(self._client, cand)
            if art:
                evidence.append(art); ran.append("host_header_ssrf")

        proposal.status = "EXECUTED"
        self.log.append(AuthorizedActionRecord(
            proposal_id=proposal.proposal_id, operator=operator, action="executed",
            approved_methods=list(approved_methods),
            evidence_collected=[a.evidence_type for a in evidence],
        ))
        return evidence

    def decline(self, proposal: FindingProposal, operator: str, reason: str = "") -> None:
        if not operator or not operator.strip():
            raise ValueError("decline() requires a non-empty operator identity.")
        proposal.status = "DECLINED"
        self.log.append(AuthorizedActionRecord(
            proposal_id=proposal.proposal_id, operator=operator, action="declined",
            approved_methods=[], evidence_collected=[], reason=reason,
        ))

    def approve_pivots(
        self, pivots: list[PivotTarget], operator: str,
    ) -> list[PivotTarget]:
        """Log operator approval of specific pivot targets and return them
        for the caller to add to the execution queue. This function does
        not itself send any request or touch pivot_queue — the caller
        (core/agent.py) does that, exactly once, with this return value."""
        if not operator or not operator.strip():
            raise ValueError("approve_pivots() requires a non-empty operator identity.")
        self.log.append(AuthorizedActionRecord(
            proposal_id="pivots:" + ",".join(p.host for p in pivots),
            operator=operator, action="pivots_approved",
            approved_methods=[], evidence_collected=[p.host for p in pivots],
        ))
        return pivots
