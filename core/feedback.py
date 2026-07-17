"""
HELLHOUND SSRF v5.0 - Phase 10: Adaptive Feedback Loop
=========================================================
v5 additions:
  [v5-NEW] Known-exploits cross-reference propagation — when a confirmed
           finding has port_state_map evidence with open ports, looks up
           those ports in the KnownExploit registry and adds exploit refs
           to sibling findings on the same host.
  [v5-NEW] K8s / ECS pattern propagation — a confirmed kubernetes_api or
           ecs_task_metadata evidence bumps all queued candidates on the
           same RFC1918 host to HIGH tier.
  [v5-NEW] OpenAPI-sourced candidate priority boost — confirmed finding on
           an OpenAPI-sourced candidate bumps sibling OpenAPI candidates
           on the same API path prefix to HIGH tier.
"""

from __future__ import annotations
import re
from urllib.parse import urlparse

from core.models import Candidate, EvidenceArtifact, PreScoreTier


# ---------------------------------------------------------------------------
# 1. Pattern propagation (Invicti vulnerability-group model)
# ---------------------------------------------------------------------------

def _endpoint_shape(url: str) -> str:
    path = urlparse(url).path
    path = re.sub(r"/v\d+(\.\d+)?", "/vN", path)
    path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return path


def propagate_pattern(
    confirmed: Candidate,
    queue: list[Candidate],
) -> list[Candidate]:
    """
    Bumps queued candidates sharing confirmed's parameter + endpoint shape
    to HIGH tier. v5: also propagates for OpenAPI siblings on same path prefix.
    """
    from core.context_classifier import classify_context

    confirmed_shape = _endpoint_shape(confirmed.target_url)
    confirmed_prefix = "/".join(urlparse(confirmed.target_url).path.split("/")[:3])
    bumped: list[Candidate] = []

    for cand in queue:
        if cand.candidate_id == confirmed.candidate_id:
            continue
        if cand.pre_score_tier == PreScoreTier.HIGH:
            continue
        if "infra_noise" in cand.confidence_reduction_flags:
            continue  # don't bump noise-flagged candidates

        # Original: same param + same endpoint shape
        same_param  = cand.parameter.lower() == confirmed.parameter.lower()
        same_shape  = _endpoint_shape(cand.target_url) == confirmed_shape

        # [v5-NEW] OpenAPI sibling: same API path prefix
        openapi_sib = (
            getattr(cand, "openapi_sourced", False)
            and urlparse(cand.target_url).path.startswith(confirmed_prefix)
        )

        if (same_param and same_shape) or openapi_sib:
            cand.pre_score_tier = PreScoreTier.HIGH
            cand.pre_score_reasons.append(
                f"propagated: sibling of confirmed finding on {confirmed.target_url}"
            )
            classify_context(cand)
            bumped.append(cand)

    return bumped


# ---------------------------------------------------------------------------
# 2. WAF-chain propagation
# ---------------------------------------------------------------------------

def propagate_waf_chain(
    fingerprinted: Candidate,
    queue: list[Candidate],
) -> list[Candidate]:
    from core.waf_detector import get_mutation_chain

    host    = urlparse(fingerprinted.target_url).netloc
    updated: list[Candidate] = []

    for cand in queue:
        if cand.candidate_id == fingerprinted.candidate_id:
            continue
        if urlparse(cand.target_url).netloc != host:
            continue
        if cand.waf_vendor is not None:
            continue

        cand.waf_vendor     = fingerprinted.waf_vendor
        cand.mutation_chain = get_mutation_chain(cand.waf_vendor)
        updated.append(cand)

    return updated


# ---------------------------------------------------------------------------
# 3. IMDSv2 escalation re-probe
# ---------------------------------------------------------------------------

async def maybe_escalate_imdsv2(
    client,
    candidate: Candidate,
    cloud_artifact: EvidenceArtifact,
) -> EvidenceArtifact | None:
    if cloud_artifact.extra.get("provider") != "aws":
        return None

    import json
    from pathlib import Path

    cloud_cfg = json.loads(
        (Path(__file__).parent / "payloads" / "cloud_metadata.json").read_text()
    )["aws"]

    candidate.headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
    token_result = await client.send(
        candidate,
        payload_value=cloud_cfg["imdsv2_token_path"],
        payload_category="imdsv2_token",
    )
    candidate.headers.pop("X-aws-ec2-metadata-token-ttl-seconds", None)

    token_value = token_result.body_snippet.strip()
    if token_result.status_code != 200 or not token_value or len(token_value) > 200:
        return None

    token_header = cloud_cfg["imdsv2_header"]
    candidate.headers[token_header] = token_value
    probe = await client.send(
        candidate,
        payload_value=cloud_cfg["probe_paths"][0],
        payload_category="imdsv2_escalation",
    )
    candidate.headers.pop(token_header, None)

    markers_found = [
        m for m in cloud_cfg["schema_markers"]
        if m.lower() in probe.body_snippet.lower()
    ]
    if len(markers_found) >= 2:
        return EvidenceArtifact(
            evidence_type="cloud_metadata_schema",
            summary=(
                "AWS IMDSv2 ALSO accessible via this SSRF — "
                "token-based metadata access succeeded. "
                "IMDSv1/v2 hop-limit restrictions do not protect this endpoint."
            ),
            raw_evidence=probe.body_snippet,
            schema_matched=True,
            extra={
                "provider":    "aws",
                "escalation":  "imdsv2",
                "markers":     markers_found,
                "raw_request": probe.raw_request,
            },
        )
    return None


# ---------------------------------------------------------------------------
# 4. [v5-NEW] Known-exploits cross-reference propagation
# ---------------------------------------------------------------------------

def propagate_known_exploits(
    evidence: list[EvidenceArtifact],
    queue: list[Candidate],
    target_host: str,
) -> list[dict]:
    """
    When a port_state_map artifact reveals open ports on `target_host`,
    cross-references against the KnownExploit registry and returns a list
    of exploit reference dicts for embedding in the finding.

    Also bumps any queued candidates on the same internal host to HIGH tier
    if a critical exploit is matched.
    """
    from core.known_exploits import get_registry
    from core.context_classifier import classify_context

    open_ports: list[int] = []
    for art in evidence:
        if art.evidence_type == "port_state_map":
            open_ports.extend(art.extra.get("open_ports", []))

    if not open_ports:
        return []

    registry = get_registry()
    exploits = registry.lookup(open_ports)
    if not exploits:
        return []

    # Bump same-host queued candidates if critical exploit matched
    has_critical = any(e.escalate_to == "critical" for e in exploits)
    if has_critical:
        for cand in queue:
            if urlparse(cand.target_url).hostname == target_host:
                if cand.pre_score_tier != PreScoreTier.HIGH:
                    cand.pre_score_tier = PreScoreTier.HIGH
                    cand.pre_score_reasons.append(
                        f"propagated: critical exploit reachable on {target_host} "
                        f"via SSRF — bumped to HIGH tier"
                    )
                    classify_context(cand)

    return [
        {
            "service":      e.service,
            "port":         e.port,
            "cve":          e.cve,
            "cvss_score":   e.cvss_score,
            "exploit_type": e.exploit_type,
            "description":  e.description,
        }
        for e in exploits
    ]


# ---------------------------------------------------------------------------
# 5. [v5-NEW] K8s / ECS special pattern propagation
# ---------------------------------------------------------------------------

def propagate_cloud_container_pattern(
    evidence: list[EvidenceArtifact],
    queue: list[Candidate],
) -> list[Candidate]:
    """
    When Kubernetes API or ECS task metadata evidence is confirmed,
    bumps ALL remaining queued candidates on the same RFC1918 network
    to HIGH tier — an attacker with SSRF into a K8s cluster will
    probe every endpoint.
    """
    from core.context_classifier import classify_context

    has_k8s = any(a.evidence_type == "kubernetes_api" for a in evidence)
    has_ecs = any(a.evidence_type == "ecs_task_metadata" for a in evidence)

    if not (has_k8s or has_ecs):
        return []

    bumped: list[Candidate] = []
    for cand in queue:
        if cand.pre_score_tier == PreScoreTier.HIGH:
            continue
        try:
            import ipaddress
            host = urlparse(cand.target_url).hostname or ""
            ip   = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback:
                cand.pre_score_tier = PreScoreTier.HIGH
                label = "K8s cluster" if has_k8s else "ECS task network"
                cand.pre_score_reasons.append(
                    f"propagated: {label} reachable via SSRF — all internal candidates bumped"
                )
                classify_context(cand)
                bumped.append(cand)
        except (ValueError, TypeError):
            pass

    return bumped
