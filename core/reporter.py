"""
HELLHOUND SSRF v5.0 - Phase 9: Reporting & Evidence Packaging
================================================================
v5 additions:
  [v5-NEW] known_exploit_refs embedded in all evidence-tier findings
  [v5-NEW] kubernetes_api, ecs_task_metadata, oracle_cloud evidence type
           mappings for sub_agent and vuln_type
  [v5-NEW] SARIF 2.1.0 includes exploit_refs in properties.tags
  [v5-NEW] curl PoC corrected for HOST_HEADER and CRLF_INJECTION contexts
  [v5-NEW] confidence_reduction_flags surfaced in finding.details
"""

from __future__ import annotations
import json
from pathlib import Path

from core.models import (
    Candidate, ConfidenceTier, EvidenceArtifact,
    Finding, KnownExploit, ScanReport,
)
from core import scoring
from core.differential import describe_signature

AGENT_GROUP = "agent_detection"

_SUB_AGENT = {
    "cloud_metadata_schema": "CloudMetadataEvidenceEngine",
    "protocol_banner":       "ProtocolBannerFingerprintEngine",
    "file_read":             "FileReadEvidenceEngine",
    "port_state_map":        "PortStateDiscoveryEngine",
    "kubernetes_api":        "KubernetesAPIEvidenceEngine",
    "ecs_task_metadata":     "ECSTaskMetadataEngine",
    "oracle_cloud":          "OracleCloudIMDSEngine",
    "crlf_injection":        "CRLFInjectionEngine",
    "host_header_ssrf":      "HostHeaderSSRFEngine",
}

_VULN_TYPE = {
    "cloud_metadata_schema": "ssrf_cloud_metadata_exposure",
    "protocol_banner":       "ssrf_internal_service_fingerprint",
    "file_read":             "ssrf_arbitrary_file_read",
    "port_state_map":        "ssrf_internal_network_discovery",
    "kubernetes_api":        "ssrf_kubernetes_api_exposure",
    "ecs_task_metadata":     "ssrf_ecs_task_metadata_exposure",
    "oracle_cloud":          "ssrf_oracle_cloud_imds_exposure",
    "crlf_injection":        "crlf_header_injection",
    "host_header_ssrf":      "ssrf_host_header_injection",
}


# ---------------------------------------------------------------------------
# Building findings
# ---------------------------------------------------------------------------

def build_tentative_finding(
    candidate: Candidate,
    result,
) -> Finding:
    s = scoring.score(ConfidenceTier.TENTATIVE)
    return Finding(
        agent_group=AGENT_GROUP,
        sub_agent="ContextualSSRFDifferentialDetector",
        vulnerability_type="ssrf_suspected_anomaly",
        category="ssrf",
        severity=s["severity"],
        confidence=s["confidence"],
        cvss_vector=s["cvss_vector"],
        target_url=candidate.target_url,
        affected_parameter=candidate.parameter,
        description=(
            f"The '{candidate.parameter}' parameter "
            f"(context: {candidate.context_class.value}) "
            f"produced an anomalous differential response when sent an SSRF probe. "
            f"NOT independently confirmed — review manually."
        ),
        observation=describe_signature(result),
        proof_of_concept=_curl_poc(candidate, result),
        remediation=_generic_remediation(),
        details={
            "method":          candidate.method,
            "param_location":  candidate.param_location.value,
            "context_class":   candidate.context_class.value,
            "payload":         result.payload,
            "detection_method": "differential_anomaly",
            "waf_vendor":      candidate.waf_vendor,
            "composite_z":     round(result.composite_z, 3),
            "z_timing":        round(result.z_timing, 3),
            "z_status":        round(result.z_status, 3),
            "z_content_length": round(result.z_content_length, 3),
            "z_redirect":      result.z_redirect,
            "error_class":     result.error_class,
            "baseline_time":   f"{candidate.baseline.timing_mean:.2f}s" if candidate.baseline else None,
            "response_time":   f"{result.elapsed:.2f}s",
            "confidence_reduction_flags": candidate.confidence_reduction_flags,
            "extracted_data":  None,
            "raw_request":     result.raw_request,
            "raw_response":    result.raw_response,
        },
    )


def build_firm_finding(
    candidate: Candidate,
    result,
    token: str,
    collab_host: str,
    async_pattern: bool,
) -> Finding:
    s = scoring.score(ConfidenceTier.FIRM)
    return Finding(
        agent_group=AGENT_GROUP,
        sub_agent="OOBCorrelationEngine",
        vulnerability_type="ssrf_blind_oob_confirmed",
        category="ssrf",
        severity=s["severity"],
        confidence=s["confidence"],
        cvss_vector=s["cvss_vector"],
        target_url=candidate.target_url,
        affected_parameter=candidate.parameter,
        description=(
            f"The '{candidate.parameter}' parameter caused the server to make an outbound "
            f"DNS/HTTP request to attacker-controlled infrastructure, confirming blind SSRF."
            + (
                " Async/queued processing pattern detected."
                if async_pattern else ""
            )
        ),
        observation=(
            f"OOB interaction received for token {token} on {collab_host}. "
            + ("Async job pattern detected (multi-callback gap ≥1.5s)." if async_pattern else "")
        ),
        proof_of_concept=_curl_poc(
            candidate, result, oob_value=f"http://{token}.{collab_host}/"
        ),
        remediation=(
            "Block outbound requests to attacker-controlled or arbitrary external hosts. "
            "Enforce an allow-list for webhook/callback destinations."
        ),
        details={
            "method":          candidate.method,
            "param_location":  candidate.param_location.value,
            "context_class":   candidate.context_class.value,
            "detection_method": "oob_callback",
            "oob_token":       token,
            "async_processing_detected": async_pattern,
            "confidence_reduction_flags": candidate.confidence_reduction_flags,
            "extracted_data":  None,
            "raw_request":     result.raw_request if result else "",
            "raw_response":    result.raw_response if result else "",
        },
    )


def build_evidence_finding(
    candidate: Candidate,
    artifact: EvidenceArtifact,
    tier: ConfidenceTier = ConfidenceTier.CERTAIN,
    chain_note: str | None = None,
    known_exploits: list[KnownExploit] | None = None,
) -> Finding:
    s = scoring.score(tier, known_exploits)
    description = _evidence_description(candidate, artifact)
    if chain_note:
        description += f" {chain_note}"

    return Finding(
        agent_group=AGENT_GROUP,
        sub_agent=_SUB_AGENT.get(artifact.evidence_type, "EvidenceEngine"),
        vulnerability_type=_VULN_TYPE.get(artifact.evidence_type, "ssrf_confirmed"),
        category="ssrf",
        severity=s["severity"],
        confidence=s["confidence"],
        cvss_vector=s["cvss_vector"],
        target_url=candidate.target_url,
        affected_parameter=candidate.parameter,
        description=description,
        observation=artifact.summary,
        proof_of_concept=_curl_poc(
            candidate, None,
            raw_payload=(
                artifact.extra.get("path") or
                artifact.extra.get("file_path") or
                artifact.extra.get("url") or ""
            ),
        ),
        remediation=_remediation_for(artifact.evidence_type),
        known_exploit_refs=s.get("exploit_refs", []),
        details={
            "method":           candidate.method,
            "param_location":   candidate.param_location.value,
            "context_class":    candidate.context_class.value,
            "detection_method": "evidence_fingerprint",
            "evidence_type":    artifact.evidence_type,
            "waf_vendor":       candidate.waf_vendor,
            "confidence_reduction_flags": candidate.confidence_reduction_flags,
            "extracted_data": {
                "type":             artifact.evidence_type,
                "schema_matched":   artifact.schema_matched,
                "preview":          artifact.raw_evidence[:500],
                "saved_path":       artifact.saved_path,
                **{
                    k: v for k, v in artifact.extra.items()
                    if k not in ("raw_request", "raw_response")
                },
            },
            "raw_request":  artifact.extra.get("raw_request", ""),
            "raw_response": artifact.extra.get("raw_response", ""),
        },
    )


def build_chain_pivot_finding(
    candidate: Candidate,
    pivots: list,
    token: str | None,
    collab_host: str | None,
    known_exploits: list[KnownExploit] | None = None,
) -> Finding:
    s = scoring.score(ConfidenceTier.CRITICAL_PLUS, known_exploits)
    hosts = ", ".join(p.host for p in pivots)
    k8s_notes = " ".join(
        p.notes for p in pivots if getattr(p, "is_kubernetes", False)
    )
    return Finding(
        agent_group=AGENT_GROUP,
        sub_agent="ChainedSSRFDetector",
        vulnerability_type="ssrf_chained_internal_pivot",
        category="ssrf",
        severity=s["severity"],
        confidence=s["confidence"],
        cvss_vector=s["cvss_vector"],
        target_url=candidate.target_url,
        affected_parameter=candidate.parameter,
        description=(
            f"The '{candidate.parameter}' parameter enables a multi-hop SSRF chain. "
            f"Blind SSRF callback originated from internal RFC1918 address(es): {hosts}."
            + (f" K8s API server reachable: {k8s_notes}" if k8s_notes else "")
        ),
        observation="; ".join(p.notes for p in pivots),
        proof_of_concept=_curl_poc(
            candidate, None,
            oob_value=f"http://{token}.{collab_host}/" if token and collab_host else "",
        ),
        remediation=(
            "Apply network segmentation so the application server cannot reach other "
            "internal hosts/segments. Block egress to RFC1918 ranges from this service."
        ),
        known_exploit_refs=s.get("exploit_refs", []),
        exploit_chain=[p.host for p in pivots],
        details={
            "method":           candidate.method,
            "param_location":   candidate.param_location.value,
            "context_class":    candidate.context_class.value,
            "detection_method": "oob_chained_pivot",
            "oob_token":        token,
            "pivot_hosts":      [p.host for p in pivots],
            "confidence_reduction_flags": candidate.confidence_reduction_flags,
            "extracted_data": {
                "type":   "chained_pivot",
                "pivots": [
                    {
                        "host":             p.host,
                        "hop_count":        p.hop_count,
                        "discovery_method": p.discovery_method,
                        "notes":            p.notes,
                        "is_kubernetes":    getattr(p, "is_kubernetes", False),
                        "is_ecs":           getattr(p, "is_ecs", False),
                    }
                    for p in pivots
                ],
            },
            "raw_request":  "",
            "raw_response": "",
        },
    )


# ---------------------------------------------------------------------------
# PoC builder
# ---------------------------------------------------------------------------

def _curl_poc(
    candidate: Candidate,
    result=None,
    oob_value: str | None = None,
    raw_payload: str = "",
) -> str:
    import urllib.parse
    from core.models import ContextClass

    value = oob_value or (result.payload if result else raw_payload)

    # HOST_HEADER context: inject via header
    if candidate.context_class == ContextClass.HOST_HEADER:
        return (
            f'curl -sk -H "{candidate.parameter}: {value}" '
            f'"{candidate.target_url}"'
        )

    loc = candidate.param_location.value
    if loc == "query":
        qs  = urllib.parse.urlencode({candidate.parameter: value})
        sep = "&" if "?" in candidate.target_url else "?"
        return f'curl -sk "{candidate.target_url}{sep}{qs}"'
    if loc == "header":
        return (
            f'curl -sk -H "{candidate.parameter}: {value}" '
            f'"{candidate.target_url}"'
        )
    if loc == "body_json":
        body = json.dumps({candidate.parameter: value})
        return (
            f"curl -sk -X {candidate.method} "
            f"-H 'Content-Type: application/json' "
            f"-d '{body}' "
            f'"{candidate.target_url}"'
        )
    return (
        f"curl -sk -X {candidate.method} "
        f"-d \"{candidate.parameter}={urllib.parse.quote(str(value))}\" "
        f'"{candidate.target_url}"'
    )


# ---------------------------------------------------------------------------
# Descriptions and remediations
# ---------------------------------------------------------------------------

def _evidence_description(candidate: Candidate, artifact: EvidenceArtifact) -> str:
    m = {
        "cloud_metadata_schema": (
            f"The '{candidate.parameter}' parameter allows the server to fetch "
            f"cloud instance metadata. Response body matches the documented schema."
        ),
        "protocol_banner": (
            f"The '{candidate.parameter}' parameter allows the server to reach an "
            f"internal network service. A read-only protocol probe returned a "
            f"confirming banner."
        ),
        "file_read": (
            f"The '{candidate.parameter}' parameter allows arbitrary local file reads "
            f"via file:// scheme."
        ),
        "port_state_map": (
            f"The '{candidate.parameter}' parameter allows the server to connect to "
            f"arbitrary internal hosts/ports."
        ),
        "kubernetes_api": (
            f"The '{candidate.parameter}' parameter allows the server to reach the "
            f"Kubernetes API server. Cluster takeover may be possible."
        ),
        "ecs_task_metadata": (
            f"The '{candidate.parameter}' parameter allows the server to reach the "
            f"AWS ECS Task Metadata Service, exposing cluster credentials."
        ),
        "oracle_cloud": (
            f"The '{candidate.parameter}' parameter allows the server to reach the "
            f"Oracle Cloud IMDS endpoint."
        ),
        "crlf_injection": (
            f"The '{candidate.parameter}' parameter is vulnerable to CRLF injection — "
            f"attacker-controlled headers were injected into the HTTP response."
        ),
    }
    return m.get(artifact.evidence_type, artifact.summary)


def _remediation_for(evidence_type: str) -> str:
    r = {
        "cloud_metadata_schema": (
            "Block application servers from reaching 169.254.169.254 / "
            "metadata.google.internal via egress firewall rules. "
            "Enforce IMDSv2 on AWS, require Metadata-Flavor header on GCP."
        ),
        "kubernetes_api": (
            "Apply Kubernetes NetworkPolicy to block pod-to-API-server traffic "
            "from the web tier. Enforce RBAC with minimal cluster permissions. "
            "Use IRSA / Workload Identity instead of instance credentials."
        ),
        "ecs_task_metadata": (
            "Block access to 169.254.170.2 from the ECS task network namespace "
            "unless explicitly required. Use IAM task roles with least-privilege permissions."
        ),
        "protocol_banner": (
            "Apply network segmentation so application servers cannot reach "
            "internal service ports. Disable gopher://, dict:// schemes."
        ),
        "file_read": (
            "Restrict URL-fetching to http(s):// via an explicit scheme allow-list. "
            "Reject file://, php://, gopher://, dict://, etc."
        ),
        "port_state_map": (
            "Apply egress network policies restricting application servers to only "
            "the external hosts/ports required for business functionality."
        ),
        "crlf_injection": (
            "Sanitise all user-supplied values used in HTTP headers — strip or "
            "reject input containing CR (\\r) and LF (\\n) characters. "
            "Use a safe HTTP library that prevents header injection."
        ),
    }
    return r.get(evidence_type, _generic_remediation())


def _generic_remediation() -> str:
    return (
        "Validate and restrict outbound requests triggered by user-controlled "
        "input to an allow-list of expected hosts/schemes. Apply network-level "
        "egress controls (deny RFC1918, link-local, and cloud metadata ranges "
        "from application servers)."
    )


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Cross-parameter deduplication
# ---------------------------------------------------------------------------
#
# WHY THIS EXISTS: prescore/spider_adapter deliberately expands one
# discovered endpoint into several CANDIDATE parameter names when the real
# spec/spider source didn't tell us which field is actually read as a URL
# (e.g. a webhook-registration endpoint with an observed field named
# "callback" gets probed under a handful of plausible aliases: url,
# callback_url, target, src...). That's the right call for RECALL — better
# to over-guess than miss the real sink name. But it means a single genuine
# anomaly can currently surface as N "findings", one per guessed alias, all
# citing an IDENTICAL differential signal — which is also the tell that lets
# us safely collapse them: if the response didn't change AT ALL based on
# which parameter name carried the payload, that's not N independently
# vulnerable parameters, it's one endpoint-level observation (at best) or a
# guessed-parameter false-positive pattern (at worst — see the ≥3-alias
# demotion below). This only ever touches TENTATIVE/unconfirmed differential
# findings. OOB-confirmed and evidence-confirmed findings are NOT touched —
# each carries its own independent, per-candidate confirmation (a unique OOB
# token, or structural evidence actually observed for that specific
# candidate), so sharing an endpoint with another finding proves nothing
# about either being spurious.

_CANONICAL_PARAM_NAMES = (
    "url", "target_url", "webhook_url", "callback_url", "target", "callback", "src",
)


def _pick_representative(bucket: list[Finding]) -> Finding:
    """Prefer a canonical SSRF-param name over a generic guess as the
    survivor of a collapsed duplicate group, so the report reads naturally."""
    for name in _CANONICAL_PARAM_NAMES:
        for f in bucket:
            if f.affected_parameter == name:
                return f
    return max(bucket, key=lambda f: f.details.get("composite_z", 0.0))


def dedupe_findings(report: ScanReport) -> dict:
    """
    Collapses findings that share an endpoint+method AND produced an
    identical underlying signal across different GUESSED parameter-name
    aliases (url/target_url/src/target-style guesses at one unknown real
    sink field — see spider_adapter._expand_endpoint). Mutates
    report.findings in place. Returns stats for the phase summary.

    Covers three detection methods, each with its own signature:
      - differential_anomaly : composite_z + status/length/redirect deltas
      - oob_chained_pivot     : the sorted set of pivot hosts reached
      - evidence_fingerprint  : evidence_type + schema-match outcome

    [FIX, found via live testing] The original version of this function
    only covered differential_anomaly. Testing the native-crawl integration
    turned up a real gap: a single endpoint that reacts identically to ANY
    POST body (a common pattern when the real sink parameter isn't one of
    the guessed names, or the anomaly isn't parameter-driven at all) still
    produces N independent CRITICAL+ chain-pivot findings — one per guessed
    alias — because build_chain_pivot_finding/build_evidence_finding never
    matched the old detection_method=="differential_anomaly" filter. Same
    underlying bug pattern Alpha originally reported, just past the point
    where it only affected TENTATIVE findings.

    IMPORTANT SAFETY BOUNDARY: collapsing is restricted to candidates whose
    param_location is query/body_form/body_json — the locations where the
    pipeline genuinely GUESSES at multiple alias names for one unknown real
    parameter. header/cookie-location candidates are NEVER collapsed
    together, even with an identical signal, because different header
    names (X-Forwarded-Host vs X-Original-URL vs X-Forwarded-For) are
    frequently handled by different middleware layers in real
    applications — collapsing those would hide independently-real,
    independently-fixable attack vectors, not just noise.

    Confidence handling differs by method: differential_anomaly dupes get
    DEMOTED (the signal was only ever a weak, unconfirmed guess, and 3+
    identical guesses is itself evidence the guess is wrong). Evidence- and
    chain-confirmed dupes are collapsed for report readability but are NOT
    demoted — the underlying finding (a real port-scan hit, a real pivot to
    an internal host) is still genuinely verified regardless of which
    guessed alias triggered it; only the redundant parameter-level noise
    is removed.
    """
    from collections import defaultdict

    _ALIAS_LOCATIONS = {"query", "body_form", "body_json"}
    eps = 0.05  # z-score tolerance for "same" signal, given float rounding

    def _signature(f: Finding):
        d = f.details
        method = d.get("detection_method")
        if method == "differential_anomaly" and "composite_z" in d:
            return ("differential_anomaly", (
                round(d.get("composite_z", 0.0) / eps),
                round((d.get("z_status") or 0.0) / eps),
                round((d.get("z_content_length") or 0.0) / eps),
                d.get("z_redirect") or 0,
            ))
        if method == "oob_chained_pivot" and d.get("pivot_hosts"):
            return ("oob_chained_pivot", tuple(sorted(d["pivot_hosts"])))
        if method == "evidence_fingerprint":
            ed = d.get("extracted_data", {})
            return ("evidence_fingerprint", (d.get("evidence_type"), ed.get("schema_matched")))
        return None  # not an eligible detection method — never collapsed

    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in report.findings:
        groups[(f.target_url, f.details.get("method", ""))].append(f)

    stats = {"groups_collapsed": 0, "findings_merged": 0, "demoted": 0}
    survivors: list[Finding] = []

    for group in groups.values():
        if len(group) < 2:
            survivors.extend(group)
            continue

        dedup_pool = [
            f for f in group
            if f.details.get("param_location") in _ALIAS_LOCATIONS
            and _signature(f) is not None
        ]
        untouched = [f for f in group if f not in dedup_pool]
        survivors.extend(untouched)

        if len(dedup_pool) < 2:
            survivors.extend(dedup_pool)
            continue

        sig_buckets: dict[tuple, list[Finding]] = defaultdict(list)
        for f in dedup_pool:
            sig_buckets[_signature(f)].append(f)

        for sig, bucket in sig_buckets.items():
            if len(bucket) == 1:
                survivors.extend(bucket)
                continue

            method = sig[0]
            stats["groups_collapsed"] += 1
            stats["findings_merged"]  += len(bucket) - 1

            rep      = _pick_representative(bucket)
            aliases  = sorted({f.affected_parameter for f in bucket if f is not rep})
            rep.details["duplicate_parameter_aliases"] = aliases

            if method == "differential_anomaly":
                rep.details["dedup_note"] = (
                    f"{len(bucket)} different parameter names on this endpoint produced an "
                    f"IDENTICAL differential signal (composite_z={rep.details.get('composite_z')}, "
                    f"same status/content-length/redirect deltas). The response did not change "
                    f"based on which parameter carried the payload — that's the signature of an "
                    f"endpoint-level response quirk, not {len(bucket)} independently vulnerable "
                    f"parameters. Verify manually before treating each alias as a separate issue. "
                    f"Collapsed aliases: {', '.join(aliases)}."
                )
                # 3+ different guessed names all producing the identical signal
                # is a stronger tell that NONE of them is the real sink name —
                # demote so a guessed-parameter false-positive pattern doesn't
                # read with the same weight as a real per-parameter differential
                # hit on an unconfirmed (TENTATIVE) finding.
                if len(bucket) >= 3 and getattr(rep, "confidence_tier", "").upper() == "TENTATIVE":
                    stats["demoted"] += 1
                    rep.details["dedup_note"] += (
                        " Demoted: likely a guessed-parameter false-positive pattern, not a "
                        "confirmed per-parameter sink."
                    )
                    rep.confidence = "VERY LOW"
            else:
                rep.details["dedup_note"] = (
                    f"{len(bucket)} different guessed parameter names on this endpoint all "
                    f"produced the same verified evidence ({method}). The underlying finding "
                    f"is still confirmed — it is not clear WHICH parameter is the real sink, "
                    f"only that this endpoint is reachable/exploitable regardless of which "
                    f"guessed name carried the payload. Confidence is NOT reduced (the evidence "
                    f"itself is real), only the redundant per-alias noise is collapsed. "
                    f"Collapsed aliases: {', '.join(aliases)}."
                )
                # Deliberately no confidence demotion here — see docstring.

            survivors.append(rep)

    report.findings = survivors
    return stats


def write_json_report(report: ScanReport, output_path: "str | Path") -> Path:
    path = Path(output_path)
    path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
    return path


def write_sarif_report(report: ScanReport, output_path: "str | Path") -> Path:
    """SARIF 2.1.0 export with exploit refs in properties."""
    rules: dict[str, dict] = {}
    results: list[dict]    = []

    for finding in report.findings:
        rule_id = finding.vulnerability_type
        rules.setdefault(rule_id, {
            "id":               rule_id,
            "name":             rule_id.replace("_", " ").title(),
            "shortDescription": {"text": finding.description[:120]},
            "helpUri": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        })

        level = {
            "critical": "error",
            "high":     "error",
            "medium":   "warning",
            "low":      "note",
        }.get(finding.severity, "warning")

        exploit_tags = [
            f"{e['service']}:{e.get('cve','no-cve')}"
            for e in (finding.known_exploit_refs or [])
        ]

        results.append({
            "ruleId":  rule_id,
            "level":   level,
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.target_url},
                }
            }],
            "properties": {
                "confidence":          finding.confidence,
                "affected_parameter":  finding.affected_parameter,
                "sub_agent":           finding.sub_agent,
                "cvss_vector":         finding.cvss_vector,
                "exploit_chain":       finding.exploit_chain,
                "known_exploit_tags":  exploit_tags,
                "confidence_reduction": finding.details.get("confidence_reduction_flags", []),
                "id":                  finding.id,
            },
        })

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":    "HELLHOUND-SSRF",
                    "version": "5.0",
                    "rules":   list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    path = Path(output_path)
    path.write_text(json.dumps(sarif, indent=2))
    return path
