"""
RAVAGER SSRF v2.0.0 - Phase 7: Second-Order & Chained SSRF Detection
==========================================================================

This module has two distinct responsibilities:

  1. detect_cross_endpoint_ssrf() — DETECTION
     Identifies cross-endpoint SSRF chains from existing findings. Checks
     if multiple candidates on the SAME host but DIFFERENT endpoints
     produced findings, which indicates chain amplification potential.
     Pure classification — no requests sent.

  2. extract_pivot_targets() — EXTRACTION
     Derives new pivot hosts from evidence (port maps, metadata, OOB
     callbacks) for the agent to scan in subsequent hops. Pure function
     over already-collected evidence. The actual re-queuing is done by
     agent.py's pivot loop, gated by AuthorizedActionGate.approve_pivots().

v5 additions:
  [v5-NEW] Kubernetes API server pivot
  [v5-NEW] ECS task metadata pivot
  [v5-NEW] Known-exploits cross-reference on open ports
"""

from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass, field

from core.models import Candidate, EvidenceArtifact

# K8s API ports worth pivoting into
_K8S_PORTS = {443, 6443, 8443}
# K8s API response markers
_K8S_API_MARKERS = re.compile(
    r"apiVersion|\"kind\":|\"namespaces\"|\"pods\"|\"services\"|gitVersion|major.*minor",
    re.I,
)


@dataclass
class PivotTarget:
    host:                       str
    discovered_via_candidate_id: str
    hop_count:                  int
    discovery_method:           str
    notes:                      str  = ""
    open_ports:                 list[int] = field(default_factory=list)
    is_kubernetes:              bool = False
    is_ecs:                     bool = False
    known_exploit_notes:        str  = ""


def extract_pivot_targets(
    candidate: Candidate,
    evidence: list[EvidenceArtifact],
    oob_internal_addrs: list[str],
    dns_rebind_targets: list[str] | None = None,
    current_hop: int = 1,
    max_hops: int = 3,
) -> list[PivotTarget]:
    """
    Examines Phase 5/6 outputs and returns new internal-host pivot targets
    to re-queue as Phase 0 candidates. Bounded to max_hops to prevent
    runaway scanning across an entire internal network.
    """
    if current_hop > max_hops:
        return []

    pivots: list[PivotTarget] = []

    # ---- 1. OOB callbacks from internal addresses ----------------------
    for addr in oob_internal_addrs:
        pivots.append(PivotTarget(
            host=addr,
            discovered_via_candidate_id=candidate.candidate_id,
            hop_count=current_hop,
            discovery_method="oob_remote_addr",
            notes=(
                f"Blind SSRF callback originated from internal address {addr} "
                f"via {candidate.target_url}"
            ),
        ))

    # ---- 2. DNS rebinding -------------------------------------------------
    for addr in dns_rebind_targets or []:
        pivots.append(PivotTarget(
            host=addr,
            discovered_via_candidate_id=candidate.candidate_id,
            hop_count=current_hop,
            discovery_method="dns_rebinding",
            notes=(
                f"DNS rebinding detected: hostname for {candidate.target_url} "
                f"resolved to internal address {addr} during probing "
                "(TOCTOU on hostname validation)."
            ),
        ))

    # ---- 3. Evidence-derived pivot targets --------------------------------
    for art in evidence:

        # -- port_state_map: pivot into hosts with open ports ---------------
        if art.evidence_type == "port_state_map":
            host       = art.extra.get("host", "")
            port_states = art.extra.get("port_states", {})
            open_ports = [
                int(p) for p, v in port_states.items()
                if v["state"] in ("open_http", "filtered_or_non_http_open")
            ]

            if host and _is_internal(host) and open_ports:
                pt = PivotTarget(
                    host=host,
                    discovered_via_candidate_id=candidate.candidate_id,
                    hop_count=current_hop,
                    discovery_method="port_state_map",
                    notes=f"Host {host} has open ports {open_ports} reachable via SSRF",
                    open_ports=open_ports,
                )

                # [v5-NEW] K8s pivot: port 443/6443/8443 open on RFC1918 host
                if any(p in _K8S_PORTS for p in open_ports):
                    pt.is_kubernetes = True
                    pt.notes += (
                        " — K8s API server candidate (port 443/6443/8443 open). "
                        "Attempt /api/v1/ probe on next hop."
                    )

                # [v5-NEW] Known-exploits annotation
                pt.known_exploit_notes = _annotate_known_exploits(open_ports)

                pivots.append(pt)

        # -- cloud_metadata_schema: extract internal IPs from body ----------
        elif art.evidence_type == "cloud_metadata_schema":
            for token in art.raw_evidence.split():
                clean = token.strip('",\n\r')
                if _is_internal(clean):
                    pivots.append(PivotTarget(
                        host=clean,
                        discovered_via_candidate_id=candidate.candidate_id,
                        hop_count=current_hop,
                        discovery_method="metadata_body",
                        notes=(
                            f"Internal address {clean} disclosed in cloud "
                            f"metadata response via {candidate.target_url}"
                        ),
                    ))

        # -- [v5-NEW] Kubernetes API evidence: pivot into cluster --------
        elif art.evidence_type == "kubernetes_api":
            k8s_url  = art.extra.get("url", "")
            k8s_host = _extract_host(k8s_url)
            if k8s_host:
                pivots.append(PivotTarget(
                    host=k8s_host,
                    discovered_via_candidate_id=candidate.candidate_id,
                    hop_count=current_hop,
                    discovery_method="kubernetes_api",
                    notes=(
                        f"Kubernetes API server at {k8s_host} confirmed. "
                        "Probe /api/v1/namespaces/kube-system/secrets for "
                        "cluster service-account token on next hop."
                    ),
                    is_kubernetes=True,
                    open_ports=[443, 6443],
                ))

        # -- [v5-NEW] ECS task metadata pivot ----------------------------
        elif art.evidence_type == "ecs_task_metadata":
            pivots.append(PivotTarget(
                host="169.254.170.2",
                discovered_via_candidate_id=candidate.candidate_id,
                hop_count=current_hop,
                discovery_method="ecs_task_metadata",
                notes=(
                    "ECS Task Metadata Service confirmed — probe "
                    "/v2/credentials for task IAM role credentials."
                ),
                is_ecs=True,
            ))

    # Deduplicate by host
    seen:  set[str] = set()
    unique: list[PivotTarget] = []
    for pt in pivots:
        if pt.host not in seen:
            seen.add(pt.host)
            unique.append(pt)

    return unique


def detect_dns_rebinding(
    baseline_resolved_ip: str | None,
    probe_resolved_ip: str | None,
) -> bool:
    """
    Detects DNS rebinding (TOCTOU): baseline IP ≠ probe IP AND
    baseline was public, probe is internal/loopback.
    """
    if not baseline_resolved_ip or not probe_resolved_ip:
        return False
    if baseline_resolved_ip == probe_resolved_ip:
        return False
    try:
        probe_ip    = ipaddress.ip_address(probe_resolved_ip)
        baseline_ip = ipaddress.ip_address(baseline_resolved_ip)
    except ValueError:
        return False
    return (
        not baseline_ip.is_private
        and (probe_ip.is_private or probe_ip.is_loopback)
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_internal(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _extract_host(url: str) -> str | None:
    try:
        import httpx
        return httpx.URL(url).host or None
    except Exception:
        if "://" in url:
            return url.split("://", 1)[1].split("/")[0].split(":")[0]
        return None


def _annotate_known_exploits(open_ports: list[int]) -> str:
    """
    [v5-NEW] Quick known-exploits lookup for pivot target annotation.
    Full lookup is in known_exploits.py; this is a lightweight summary.
    """
    try:
        from core.known_exploits import get_registry
        registry = get_registry()
        exploits = registry.lookup(open_ports)
        if not exploits:
            return ""
        parts = [
            f"Port {e.port} ({e.service}, {e.exploit_type}"
            + (f", {e.cve}" if e.cve else "")
            + f", CVSS {e.cvss_score})"
            for e in exploits[:3]
        ]
        return "Known exploitable services: " + "; ".join(parts)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# [v2-NEW] Cross-endpoint SSRF chain detection
# ---------------------------------------------------------------------------

@dataclass
class CrossEndpointChain:
    """Record of a cross-endpoint SSRF chain detection."""
    source_endpoint:  str
    target_endpoint:  str
    shared_host:      str
    chain_type:       str   # "multi_param_same_host" | "multi_endpoint_same_host"
    source_param:     str = ""
    target_param:     str = ""
    notes:            str = ""


def detect_cross_endpoint_ssrf(
    findings: list,
) -> list[CrossEndpointChain]:
    """
    DETECTION — identifies cross-endpoint SSRF chains from existing findings.

    Checks if multiple findings on the SAME host but DIFFERENT endpoints
    produced confirmed SSRF signals. This indicates chain amplification:
    an attacker who finds SSRF on endpoint A can use it to reach internal
    services, and if endpoint B also has SSRF, the attack surface multiplies.

    This is pure classification — no requests are sent. It operates on
    the list of Finding objects already produced by the pipeline.

    Returns:
        List of CrossEndpointChain records, one per detected chain pair.
    """
    from urllib.parse import urlparse
    from collections import defaultdict

    # Group findings by (host, path)
    host_to_endpoints: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))

    for finding in findings:
        url = getattr(finding, "target_url", "") or finding.details.get("target_url", "")
        param = getattr(finding, "affected_parameter", "") or finding.details.get("parameter", "")
        if not url:
            continue
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        path = parsed.path or "/"
        host_to_endpoints[host][path].append({
            "finding": finding,
            "param": param,
            "url": url,
        })

    chains: list[CrossEndpointChain] = []

    for host, endpoints in host_to_endpoints.items():
        if len(endpoints) < 2:
            continue

        # Cross-endpoint chain: different paths on the same host
        paths = sorted(endpoints.keys())
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                src_path, tgt_path = paths[i], paths[j]
                src_findings = endpoints[src_path]
                tgt_findings = endpoints[tgt_path]

                chains.append(CrossEndpointChain(
                    source_endpoint=src_path,
                    target_endpoint=tgt_path,
                    shared_host=host,
                    chain_type="multi_endpoint_same_host",
                    source_param=src_findings[0]["param"] if src_findings else "",
                    target_param=tgt_findings[0]["param"] if tgt_findings else "",
                    notes=(
                        f"Cross-endpoint SSRF on {host}: "
                        f"{src_path} ({len(src_findings)} finding(s)) and "
                        f"{tgt_path} ({len(tgt_findings)} finding(s)) both "
                        f"confirmed — chain amplification possible."
                    ),
                ))

        # Multi-param chain: same path, different params
        for path, path_findings in endpoints.items():
            params = {f["param"] for f in path_findings if f["param"]}
            if len(params) >= 2:
                param_list = sorted(params)
                chains.append(CrossEndpointChain(
                    source_endpoint=path,
                    target_endpoint=path,
                    shared_host=host,
                    chain_type="multi_param_same_host",
                    source_param=param_list[0],
                    target_param=param_list[1],
                    notes=(
                        f"Multi-parameter SSRF on {host}{path}: "
                        f"parameters {param_list} all confirmed SSRF — "
                        f"increases exploitation surface and bypass options."
                    ),
                ))

    return chains

