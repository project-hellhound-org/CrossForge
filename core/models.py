"""
HELLHOUND SSRF v5.0 - Core Data Models
========================================
All shared dataclasses used across the 10-phase pipeline.
v5 additions:
  - ScanMode enum  (DETECT | DETECT_EXPLOIT)
  - ContextClass: CRLF_INJECTION, HOST_HEADER added
  - Candidate: spa_catchall, auth_injected, openapi_sourced,
               confidence_reduction_flags, infra_noise_detected
  - KnownExploit dataclass for Phase 8 escalation
  - Finding: exploit_chain, known_exploit_refs, cvss_vector
  - EvidenceArtifact: k8s_api, ecs_task, oracle_cloud types added
"""

from __future__ import annotations
import uuid
import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScanMode(str, Enum):
    DETECT = "detect"               # default – read-only, safe for production
    DETECT_EXPLOIT = "detect_exploit"  # unlocks Gopher RCE / exploit modules


class ContextClass(str, Enum):
    FETCH_URL    = "fetch_url"
    REDIRECT     = "redirect"
    FILE_INCLUDE = "file_include"
    VALIDATOR    = "validator"
    CRLF_INJECTION = "crlf_injection"   # v5: CRLF/header-injection sinks
    HOST_HEADER  = "host_header"        # v5: Host / X-Forwarded-Host injection
    UNKNOWN      = "unknown"


class VulnType(str, Enum):
    """
    SSRF vulnerability surface taxonomy — 25 categories mapped directly to
    the SSRF attack surface reference compiled for CrossForge Phase 1.
    Assigned by core/vuln_classifier.py after prescore; consumed by
    context_classifier.py (overrides generic ContextClass where more specific),
    reporter.py (included in JSON/SARIF output), and eventually the exploit
    dispatcher (Phase 5 rebuild).
    """
    # ---- URL/parameter-level sinks ----------------------------------------
    URL_PARAM          = "url_param"          # classic ?url=, ?src=, ?target=
    REDIRECT_PARAM     = "redirect_param"     # ?redirect=, ?next=, ?return_to=
    CALLBACK_WEBHOOK   = "callback_webhook"   # webhook/callback/notify_url
    FEED_RSS           = "feed_rss"           # ?feed=, ?rss=, RSS readers
    HEADER_INJECTION   = "header_injection"   # X-Forwarded-Host, Referer, etc.
    AUTH_SERVICE       = "auth_service"       # OAuth/OIDC/SAML/JWKS discovery URLs
    CLOUD_STORAGE      = "cloud_storage"      # s3://, blob storage, GCS connector

    # ---- Endpoint-level sinks (path-driven) --------------------------------
    MICROSERVICE_PROXY = "microservice_proxy" # /proxy, /gateway, /forward, /route
    URL_PREVIEW        = "url_preview"        # /preview, /screenshot, /opengraph, /og
    IMAGE_PROCESSING   = "image_processing"   # /image, /avatar, /thumbnail + URL param
    PDF_SERVICE        = "pdf_service"        # /pdf, /render, /html2pdf, /report
    FILE_IMPORT        = "file_import"        # /import, /upload + remote URL param
    VIDEO_SERVICE      = "video_service"      # /video/thumbnail, /metadata, podcast
    BACKUP_RESTORE     = "backup_restore"     # /backup/restore + URL param
    CRAWL_MONITOR      = "crawl_monitor"      # /crawl, /scan, /healthcheck, /monitor

    # ---- Protocol / format level sinks -------------------------------------
    GRAPHQL_MUTATION   = "graphql_mutation"   # GraphQL mutation with URL arg
    XML_EXTERNAL       = "xml_external"       # XXE / DTD / SOAP external URL
    MULTIPART_URL      = "multipart_url"      # image_url/avatar_url in multipart form
    JSON_BODY_URL      = "json_body_url"      # {"url": "..."} in POST body
    NESTED_URL         = "nested_url"         # {"config": {"proxy": "..."}}
    GRPC_ENDPOINT      = "grpc_endpoint"      # gRPC endpoint/host/resource field

    # ---- Application feature sinks ----------------------------------------
    EMAIL_TEMPLATE     = "email_template"     # email renderer fetching remote template
    PACKAGE_IMPORT     = "package_import"     # plugin/extension/package install URL
    METADATA_EXTRACTOR = "metadata_extractor" # opengraph, favicon, link preview
    UNKNOWN            = "unknown"            # scored but not classified


class ConfidenceTier(str, Enum):
    TENTATIVE    = "tentative"    # Phase 4 anomaly only
    FIRM         = "firm"         # Phase 5 OOB confirmed
    CERTAIN      = "certain"      # Phase 6 evidence artifact
    CRITICAL_PLUS = "critical_plus"  # Phase 7 chained / Phase 8 known-exploit


class ParamLocation(str, Enum):
    QUERY           = "query"
    BODY_FORM       = "body_form"
    BODY_JSON       = "body_json"
    BODY_MULTIPART  = "body_multipart"
    HEADER          = "header"
    COOKIE          = "cookie"
    PATH            = "path"


class PreScoreTier(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


# ---------------------------------------------------------------------------
# Candidate - one (endpoint, parameter) pair moving through the pipeline
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    target_url:     str
    method:         str
    parameter:      str
    param_location: ParamLocation
    original_value: Any  = ""
    headers:        dict = field(default_factory=dict)
    cookies:        dict = field(default_factory=dict)
    body_template:  Any  = None  # full body with placeholder value in place

    # Phase 0 – pre-scoring
    pre_score:         float        = 0.0
    pre_score_tier:    PreScoreTier = PreScoreTier.LOW
    pre_score_reasons: list[str]    = field(default_factory=list)

    # Phase 1 – baseline
    baseline: Optional["BaselineProfile"] = None

    # v5 Phase 1 – infrastructure-noise detection
    # Set True when the same anomaly pattern appears on ≥3 other candidates
    # for this endpoint (load-balancer variance, CDN edge routing artefact).
    infra_noise_detected: bool = False

    # Phase 2 – context classification
    context_class:      ContextClass = ContextClass.UNKNOWN
    context_confidence: float        = 0.0
    payload_subset:     list[dict]   = field(default_factory=list)

    # Phase 1.5 – SSRF vuln-type classification (vuln_classifier.py)
    # Runs after prescore, before context classification. Provides a
    # fine-grained, attack-surface taxonomy label (VulnType enum) on
    # top of the coarser ContextClass. Used by context_classifier.py
    # (to select the most precise payload subset), reporter.py (JSON/SARIF
    # output), and eventually the Phase 5 exploit dispatcher.
    vuln_type:       VulnType = VulnType.UNKNOWN
    vuln_category:   str      = ""    # human-readable category label
    vuln_confidence: float    = 0.0   # 0.0-1.0 classifier confidence

    # Phase 3 – WAF fingerprinting
    waf_vendor:     Optional[str] = None
    mutation_chain: list[str]     = field(default_factory=list)

    # v5 – SPA catch-all flag (set by spa_detector before Phase 6)
    spa_catchall: bool = False

    # v5 – authenticated scan (set by auth_manager)
    auth_injected: bool = False

    # v5 – OpenAPI-sourced candidate
    openapi_sourced: bool = False

    # Phase 1 rebuild – GraphQL-introspection-sourced candidate. Uses a
    # dotted "variables.<name>" parameter path — see core/graphql_adapter.py
    # and core/http_client.py's [P2-FIX] for why that's required.
    graphql_sourced: bool = False

    # BUG 4 FIX: For QUERY-param candidates, the spider URL often embeds the
    # existing observed value (?to=https://github.com/...). We strip the
    # query string from target_url to prevent duplicate-param injection (see
    # spider_adapter._expand_endpoint BUG 4 FIX comment). The OTHER params
    # that were in the original URL (not the one being tested) are stored
    # here so the baseline and probe requests include them as context — the
    # server sees the same environment it normally would.
    baseline_query_context: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.baseline_query_context is None:
            self.baseline_query_context = {}

    # v5 – confidence-reduction flags (list of reason strings)
    # Examples: "infra_noise", "header_blocklisted", "spa_catchall"
    confidence_reduction_flags: list[str] = field(default_factory=list)

    # bookkeeping
    candidate_id:  str = field(default_factory=lambda: str(uuid.uuid4()))
    requests_sent: int = 0
    hop_count:     int = 0  # Phase 7 chaining depth; 0 = original candidate


# ---------------------------------------------------------------------------
# Baseline (Phase 1)
# ---------------------------------------------------------------------------

@dataclass
class BaselineProfile:
    status_codes:     list[int]   = field(default_factory=list)
    content_lengths:  list[int]   = field(default_factory=list)
    timings:          list[float] = field(default_factory=list)
    redirect_depths:  list[int]   = field(default_factory=list)
    redirect_targets: list[str]   = field(default_factory=list)
    headers_signature: list[dict] = field(default_factory=list)

    # derived stats, populated by baseline.finalize()
    timing_mean:            float         = 0.0
    timing_stddev:          float         = 0.0
    content_length_mean:    float         = 0.0
    content_length_stddev:  float         = 0.0
    dominant_status:        Optional[int] = None
    dominant_redirect_depth: int          = 0
    baseline_resolved_ip:   Optional[str] = None


# ---------------------------------------------------------------------------
# Probe result (Phase 4)
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    candidate_id:    str
    payload:         str
    payload_category: str
    status_code:     int
    content_length:  int
    elapsed:         float
    redirect_depth:  int
    redirect_chain:  list[str]
    headers:         dict
    body_snippet:    str
    raw_request:     str = ""
    raw_response:    str = ""

    # Phase 4 per-dimension z-scores
    z_status:         float = 0.0
    z_content_length: float = 0.0
    z_timing:         float = 0.0
    z_redirect:       float = 0.0
    composite_z:      float = 0.0

    # error taxonomy
    error_class: Optional[str] = None
    # connection_refused | dns_failure | timeout | success_foreign | other_error | None

    # DNS resolution at request time (for Phase 7 rebinding detection)
    resolved_ip: Optional[str] = None

    # [FIX] Shape-matched external control pairing (core/differential.py).
    # For internal-target payloads (loopback/RFC1918/cloud-metadata/etc.),
    # a same-length decoy payload pointing at a non-internal, non-routable
    # RFC 5737 documentation address is probed alongside it. control_composite_z
    # is that decoy's composite_z against the SAME baseline. is_suspicious()
    # requires the internal result to exceed the control by a real margin —
    # this is what stops "the app echoes my input, so length went up" from
    # registering as an SSRF signal, since the control payload inflates the
    # response by the same amount without ever being an internal target.
    control_composite_z: Optional[float] = None
    control_payload:     Optional[str] = None

    # [FIX] Uncapped composite scores, used only for the differential-margin
    # comparison in is_suspicious(). composite_z / control_composite_z are
    # both capped at COMPOSITE_Z_CAP for display sanity; two very different
    # anomalies (e.g. a real 300-byte data leak vs. a 100-byte block-page
    # rejection) can both clip that cap, which would erase the delta between
    # them if the margin check compared capped values. Comparing the raw,
    # uncapped scores keeps that signal intact.
    composite_z_raw:         Optional[float] = None
    control_composite_z_raw: Optional[float] = None

    # [FIX] "Structural" signal = content_length + status + redirect, with
    # timing deliberately excluded. Confirmed via testing against a real
    # vulnerable target: when the server actually makes an outbound
    # attempt, BOTH the real internal-target payload and its control
    # decoy take meaningfully longer than the "no fetch happened"
    # baseline — that's expected and true of any two distinct network
    # destinations, not a sign of which one is internal. That shared
    # timing bump was swamping the one signal that genuinely does
    # distinguish them: a real internal leak returns different content/
    # status than a blocked/failed control, even when both are slower
    # than baseline. is_suspicious() gates on this delta, not the
    # timing-inclusive one, so a real content/status difference isn't
    # masked by two payloads simply taking a similar amount of extra time.
    structural_z_raw:         Optional[float] = None
    control_structural_z_raw: Optional[float] = None


# ---------------------------------------------------------------------------
# OOB event (Phase 5)
# ---------------------------------------------------------------------------

@dataclass
class OOBEvent:
    token:        str
    candidate_id: str
    protocol:     str              # dns | http | smb
    received_at:  datetime.datetime
    remote_addr:  Optional[str] = None
    raw:          Optional[str] = None
    # v5: originating HTTP request body captured when self-hosted Interactsh
    originating_request: Optional[str] = None


# ---------------------------------------------------------------------------
# Evidence artifact (Phase 6)
# ---------------------------------------------------------------------------

@dataclass
class EvidenceArtifact:
    # v5 evidence_type additions: kubernetes_api | ecs_task_metadata |
    # oracle_cloud | crlf_injection | host_header_ssrf
    evidence_type:  str
    summary:        str
    raw_evidence:   str
    saved_path:     Optional[str] = None
    schema_matched: bool          = False
    extra:          dict          = field(default_factory=dict)


# ---------------------------------------------------------------------------
# KnownExploit (Phase 8) - cross-reference for reachable services
# ---------------------------------------------------------------------------

@dataclass
class KnownExploit:
    service:        str    # e.g. "redis", "elasticsearch", "jenkins"
    port:           int
    cve:            Optional[str] = None
    cvss_score:     float         = 0.0
    exploit_type:   str           = ""   # rce | data_exfil | auth_bypass
    description:    str           = ""
    requires_auth:  bool          = False
    escalate_to:    str           = "critical"  # severity escalation target


# ---------------------------------------------------------------------------
# Finding - final output unit
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    agent_group:        str
    sub_agent:          str
    vulnerability_type: str
    category:           str
    severity:           str
    confidence:         str
    target_url:         str
    affected_parameter: str
    description:        str
    observation:        str
    proof_of_concept:   str
    remediation:        str
    details:            dict           = field(default_factory=dict)
    cve_reference:      Optional[str]  = None
    cvss_vector:        Optional[str]  = None    # v5
    exploit_chain:      list[str]      = field(default_factory=list)  # v5
    known_exploit_refs: list[dict]     = field(default_factory=list)  # v5
    id:                 str            = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:          str            = field(
        default_factory=lambda: datetime.datetime.utcnow().isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Top-level scan report
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    status:     str            = "running"
    errors:     list[str]      = field(default_factory=list)
    gap_reason: Optional[str]  = None
    findings:   list[Finding]  = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status":     self.status,
            "errors":     self.errors,
            "gap_reason": self.gap_reason,
            "findings":   [f.to_dict() for f in self.findings],
        }
