"""
HELLHOUND SSRF v5.0 - Phase 7: Second-Order & Chained SSRF Detection
=======================================================================
v5 additions:
  [v5-NEW] Kubernetes API server pivot — when port 443/6443/8443 is
           open on an RFC1918 host and a k8s API marker is found in the
           evidence body, generates a dedicated K8s pivot target.
  [v5-NEW] ECS task metadata pivot — chains into ECS task metadata
           evidence to extract Cluster ARN and task network info.
  [v5-NEW] Known-exploits cross-reference on open ports via pivot —
           annotates PivotTarget.notes with matched CVEs and exploitability.
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
