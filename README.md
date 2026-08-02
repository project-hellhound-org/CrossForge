<p align="center">
  <img src="photo_2026-07-17_18-59-11.jpg" alt="CrossForge" width="650"/>
</p>

<h1 align="center">CrossForge</h1>
<h3 align="center">Enterprise Autonomous SSRF Detection · Exploit · Verify Agent</h3>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-2.0.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/evasion-WAF--Adaptive-critical?style=flat-square"/>
  <img src="https://img.shields.io/badge/governance-Authorized%20Action%20Gate-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

<p align="center">
  <b>10-Phase Pipeline &nbsp;·&nbsp; Authorized Action Gate &nbsp;·&nbsp; File Upload SSRF &nbsp;·&nbsp; Predictable Path Discovery &nbsp;·&nbsp; OOB-Verified &nbsp;·&nbsp; SARIF 2.1.0</b>
</p>

---

## Overview

CrossForge is an **enterprise-grade autonomous SSRF (Server-Side Request Forgery) detection, exploitation, and verification agent** built for modern web targets. It combines a SPA-aware native BFS crawler, wordlist-driven predictable path discovery, file-upload SSRF probing (SVG/DOCX/XML), GraphQL introspection, and OpenAPI spec parsing into a 10-phase detection pipeline.

What separates CrossForge from other SSRF tools is its **Authorized Action Gate** — a hard governance checkpoint between Phase 4 (detect/verify) and any operation that touches an internal service. No evidence collection, no port mapping, and no pivot queuing happens automatically. Every destructive-potential action is serialized as a `FindingProposal` and requires explicit named-operator approval via the `--review` CLI before a single request is made to an internal target.

Every finding is verified via differential z-score analysis or out-of-band OOB callback confirmation, delivered with a ready-to-run `curl` PoC, pending action proposals, and a SARIF 2.1.0 CI/CD-importable report.

---

## What's New in v2.0.0

| Area | Change |
|------|--------|
| **Authorized Action Gate** | Hard stop between Phase 4 and internal evidence collection — replaces unconditional `evidence_engine` calls. All actions require named-operator approval. |
| **Interactive `--review` CLI** | New `crossforge --review report.json` — approve/decline pending action proposals in a fresh terminal session after the scan. |
| **File Upload SSRF Probe** | New `core/file_upload_probe.py` — detects SSRF via SVG `<image>`, DOCX external relationships, and XML XXE payloads submitted to upload endpoints. |
| **Predictable Path Discovery** | New `core/path_probe.py` — probes 75+ SSRF-prone paths against the base URL using HEAD/GET. |
| **GraphQL Discovery** | New `core/graphql_adapter.py` — introspection-based candidate extraction for GraphQL-backed targets. |
| **SSRF Vulnerability Classifier** | New `core/vuln_classifier.py` — 25-category taxonomy applied after prescore. |
| **Payload Loader** | New `core/payload_loader.py` — centralized cached JSON payload file loader. |
| **Concurrent Worker Pool** | Phase 2–10 pipeline now runs N candidates concurrently (`scan.concurrency`). OOB sleep cycles overlap. |
| **Blind SSRF Fix** | OOB payloads now fire unconditionally before the `has_signal` gate — blind SSRF candidates were previously dropped before the OOB token was ever sent. |
| **WAF-Aware Differential Threshold** | WAF-detected candidates use `SUSPICIOUS_THRESHOLD_WAF` — prevents WAF response-shape noise from over-firing the differential probe. |
| **URL Reflection Signal** | New signal class: URL injected in payload appears verbatim in response body. |
| **Skipped Candidate Tracking** | Per-candidate errors in the worker pool are caught and recorded in `report.skipped_candidates` instead of cancelling all in-flight workers. |
| **Finding Deduplication** | `reporter.dedupe_findings()` collapses identical-signal cross-parameter duplicates before the final summary. |
| **Recon Intel Visibility** | Crawl stats (subdomains found, junk pages filtered, JS files analyzed) surfaced in Stage 1 lifecycle summary. |
| **Expanded `config.yaml`** | New sections: `graphql`, `path_probe`, `file_upload_probe`; expanded `crawl` with headless render escalation, quality gate, `security.txt` seeding. |

---

## Features

- **10-Phase Autonomous Pipeline** — Surface Triage → Baseline → Context Classify → WAF Fingerprint → Differential Probe → OOB Correlation → Authorized Gate → Chain/Pivot → Confidence Score → Adaptive Feedback
- **Authorized Action Gate** — Hard governance stop between detection and internal evidence/pivot operations; all active actions require named-operator approval
- **Interactive Proposal Review (`--review`)** — Separate CLI process to inspect, approve, or decline pending action proposals serialized in scan report JSON
- **File Upload SSRF Probe** — SVG (`<image href>`/`<use xlink:href>`), DOCX (external relationships), XML (XXE `SYSTEM`) — in-band detection, no OOB required
- **Predictable Path Discovery** — 75+ SSRF-prone paths across 10 categories (URL preview, microservice proxy, callback/webhook, PDF service, image processing, feed/RSS, etc.)
- **SSRF Vulnerability Classifier** — 25-category taxonomy for precise reporting and exploit routing; separate from context classifier
- **Native BFS Crawler** — Read-only crawl with static JS analysis (`fetch`/`axios`/`XHR`), form parsing, `robots.txt`/`sitemap.xml`/`security.txt` seeding, optional Playwright headless escalation for SPAs
- **OpenAPI + GraphQL Discovery** — Auto-discovers spec-derived and introspection-derived candidates additive to spider/crawl surface
- **Differential Probing** — z-score anomaly engine on timing, content-length, redirect depth, and status code; WAF-adaptive threshold; capped composite score with 2-dimension noise floor
- **OOB Blind SSRF Confirmation** — Per-candidate Interactsh tokens, background poll loop, incremental 0.5s tick polling, async pattern detection for FIRM-tier findings
- **URL Reflection Detection** — Detects payload echo in response body as a distinct signal class from differential z-score
- **Evidence Engine** — Cloud IMDS (AWS/GCP/Azure), Kubernetes API, ECS Metadata, Oracle Cloud, Redis/Memcached banner, file read — schema-matched artifact extraction
- **WAF Fingerprinting & Evasion** — 11 vendor signatures with per-vendor adaptive mutation chains; WAF-aware differential thresholding
- **Chain / Pivot Detection** — Second-order SSRF, DNS rebinding (TOCTOU IP change), K8s/ECS lateral pivot, up to `max_hops=3` depth
- **Confidence Scoring** — 4-tier model (`TENTATIVE` → `FIRM` → `CERTAIN` → `CRITICAL+`) with known-exploit escalation registry
- **Structured Reporting** — JSON + SARIF 2.1.0 output; `curl` PoC per finding; pending proposals serialization; deduplication
- **Auth-Aware** — Bearer token, API key, cookies; spider-header auto-detection; auth-redirect detection with operator warning

---

## Installation

```bash
git clone https://github.com/project-hellhound-org/CrossForge.git crossforge
cd crossforge
chmod +x install.sh
./install.sh
```

Requires **Python 3.10+**. Creates an isolated `.venv` and links `crossforge` globally via `/usr/local/bin/crossforge`.

```bash
# Manual install (development editable mode)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Optional: headless SPA rendering
pip install playwright && playwright install chromium

# Optional: full DNS record enumeration (CNAME/MX/TXT/NS)
pip install dnspython

# Verify
crossforge --version
```

---

## Usage

```bash
# Basic detect scan from Hellhound Spider JSON
crossforge --input spider_output.json http://target.com

# No spider file — CrossForge crawls & probes predictable paths itself
crossforge http://target.com

# With OOB for blind SSRF confirmation (FIRM tier findings)
crossforge --input spider.json --oob https://oast.pro

# Authenticated scan — Bearer token (JWT)
crossforge --input spider.json --bearer eyJhbGciOiJIUzI1NiJ9...

# Cookie auth
crossforge --input spider.json --cookie session=abc123

# Full pentest: OOB + auth + Burp proxy intercept
crossforge --input spider.json \
           --oob https://oast.pro \
           --bearer eyJhbGciOiJIUzI1NiJ9... \
           --proxy http://127.0.0.1:8080

# Native crawl with extra scope and deeper BFS
crossforge http://target.com \
           --crawl-scope api.target.com \
           --crawl-depth 8 \
           --oob https://oast.pro

# Exploit mode — Gopher/Dict protocol probing (requires YES ack)
crossforge --input spider.json --mode detect_exploit

# Quiet mode for CI/CD
crossforge --input candidates.json --quiet --output /tmp/crossforge-ci

# Review pending action proposals from a prior scan
crossforge --review ./reports/crossforge_report.json
```

---

## Input Formats

CrossForge accepts three input modes. All converge on the same triage and filter pipeline:

| Mode | Flag | Description |
|------|------|-------------|
| **Spider JSON** *(recommended)* | `--input spider.json` | Output from [Hellhound Spider](https://github.com/project-hellhound-org). Auto-detected by `endpoints` + `meta` keys. Full surface coverage. |
| **Flat Candidate Array** | `--input candidates.json` | JSON array of explicit candidate objects. Each entry requires `url`, `method`, `parameter`, `location`. |
| **Native Crawl + Path Discovery** | *(no `--input`)* | Provide a target URL only. CrossForge BFS-crawls, parses forms and JS, probes predictable paths, and discovers GraphQL/OpenAPI — all fed through the same pipeline. |

---

## 10-Phase Pipeline

| Phase | Name | What it does |
|-------|------|--------------|
| `00` | **Surface Triage** | Pre-score all candidates HIGH/MEDIUM/LOW via `prescore.py`; drop zero-score entries; SSRF vuln-type classification via `vuln_classifier.py` |
| `01` | **Baseline & Recon** | 5 clean samples per candidate; infra-noise detection; auth-redirect detection; predictable path discovery (`path_probe.py`); file-upload SSRF probing (`file_upload_probe.py`) |
| `02` | **Context Classifier** | Classify candidates into: `fetch_url` / `redirect` / `file_include` / `crlf_injection` / `host_header` / `file_upload` |
| `03` | **WAF Fingerprint** | 11 vendor signatures (score-based); per-vendor adaptive mutation chains; WAF-aware differential threshold adjustment |
| `04` | **Differential Probe** | z-score anomaly on timing, redirect depth, status code, content-length (cap `10.0`, 2-dim noise floor); URL reflection detection |
| `05` | **OOB Correlation** | Unconditional per-candidate Interactsh token injection; background poll loop; 0.5s incremental tick; async DNS/HTTP callback pattern detection |
| `06` | **Authorized Gate & Evidence** | `AuthorizedActionGate` hard stop — proposals generated, not auto-executed; Cloud IMDS, K8s API, ECS, Oracle Cloud, Redis, file-read only via `run_authorized_evidence()` |
| `07` | **Chain / Pivot** | DNS rebinding detection (TOCTOU IP change); pivot targets proposed via gate, not auto-queued; `max_hops=3` recursion on approved pivots only |
| `08` | **Confidence Scoring** | Known-exploit registry escalation; reduction caps; per-candidate final tier assignment |
| `09` | **Reporter & Proposals** | JSON + SARIF 2.1.0 output; `curl` PoC per finding; pending proposals serialization; finding deduplication |
| `10` | **Adaptive Feedback** | Cross-candidate pattern propagation; WAF chain caching; IMDSv2 token escalation for CERTAIN/CRITICAL+ findings |

---

## Confidence Tiers

| Tier | Signal | CVSS | Severity |
|------|--------|------|----------|
| `TENTATIVE` | Differential z-score anomaly or URL reflection — no external confirmation | 4.3 | Medium |
| `FIRM` | OOB callback confirmed — server made outbound request to Interactsh token | 6.5 | High |
| `CERTAIN` | Schema-matched evidence artifact (IMDS body, Redis banner, K8s version) — operator approved | 8.6 | Critical |
| `CRITICAL+` | Chained SSRF, K8s API access, known-exploitable internal service reached — operator approved | 9.6 | Critical |

> **Note:** `CERTAIN` and `CRITICAL+` tiers are only reachable through explicit named-operator approval via the Authorized Action Gate. No automatic scan can produce these tiers.

---

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| `detect` | *(default)* | Read-only detection. Safe for production targets. All 10 phases active; evidence and pivots gated behind `AuthorizedActionGate`. |
| `detect_exploit` | `--mode detect_exploit` | Unlocks Gopher/Dict protocol banner probing (still read-only). Requires operator `YES` acknowledgment at runtime. **Pentest-only.** |

---

## Authorized Action Gate

The **Authorized Action Gate** is the governance core of CrossForge v2.0. It replaces the previous unconditional evidence collection behaviour.

**Previous behaviour (removed):** `_process_candidate()` called `check_cloud_metadata`, `check_kubernetes_api`, `build_port_state_map`, and `feedback.maybe_escalate_imdsv2` unconditionally whenever a heuristic predicate returned True. No operator was consulted. The `config.yaml evidence.aggressive` flag — documented as gating this behaviour — was dead code never read anywhere in the codebase.

**Current behaviour:** When Phase 4/5 signals warrant evidence collection, a `FindingProposal` is created and appended to `report.pending_proposals`. No live request is made. The operator reviews proposals post-scan:

```bash
crossforge --review ./reports/crossforge_report.json
```

The interactive session shows each proposal's signals, evidence hints, and available methods. The operator selects which methods to approve. `run_authorized_evidence()` executes only those approved methods, requiring a named operator identity string.

---

## File Upload SSRF Probe

CrossForge detects SSRF triggered through uploaded file content — a class of vulnerabilities that URL-parameter probing cannot reach:

| File Type | Attack Vector | Vulnerable Parsers |
|-----------|--------------|-------------------|
| **SVG** | `<image href="..."/>` / `<use xlink:href="..."/>` | ImageMagick, librsvg, Inkscape |
| **DOCX** | External relationship in `word/_rels/document.xml.rels` | LibreOffice, python-docx, Apache POI, OOXML |
| **XML** | `<!ENTITY xxe SYSTEM "...">` | lxml, expat, SAX/DOM parsers with external entities enabled |

Detection is **in-band** (no OOB required):
- HTTP 500/502/503 — server errored while fetching file content
- Metadata keywords in response body (`ami-id`, `instance-id`, etc.)
- Response time > 2.5× candidate baseline — fetch-then-timeout pattern
- If `--oob` is set, OOB domain is embedded instead (requires callback for confirmation)

---

## Predictable Path Discovery

`core/path_probe.py` probes **75+ curated SSRF-prone paths** against the target base URL using HEAD (falling back to GET). Any path returning a non-404 response generates a `Candidate` flowing through the full Phase 0–10 pipeline.

| Category | Example Paths |
|----------|--------------|
| `url_preview` | `/api/preview`, `/link/preview`, `/unfurl` |
| `url_fetch` | `/fetch`, `/proxy`, `/api/fetch` |
| `microservice_proxy` | `/api/proxy`, `/internal/proxy`, `/connector` |
| `redirect` | `/redirect`, `/r`, `/go`, `/out` |
| `callback_webhook` | `/webhook`, `/webhooks/verify`, `/callback` |
| `metadata_extractor` | `/api/metadata`, `/og`, `/oembed` |
| `file_import` | `/import`, `/upload/url`, `/api/import` |
| `pdf_service` | `/export/pdf`, `/api/pdf`, `/render/pdf` |
| `image_processing` | `/image/resize`, `/thumbnail`, `/avatar/fetch` |
| `feed_rss` | `/feed`, `/rss`, `/atom`, `/api/rss` |

---

## SSRF Vulnerability Classifier

`core/vuln_classifier.py` classifies each candidate into one of **25 SSRF vulnerability types** using deterministic pattern matching — parameter name signals + endpoint path signals + param location. No ML, no external calls. O(n_patterns) per candidate.

**Taxonomy includes:** `URL_PARAM`, `REDIRECT_URL`, `HOST_HEADER`, `FILE_INCLUDE`, `IMAGE_PROCESSING`, `PDF_GENERATION`, `MICROSERVICE_PROXY`, `WEBHOOK_CALLBACK`, `METADATA_EXTRACTOR`, `GRAPHQL_MUTATION`, `FILE_IMPORT`, `JSON_BODY_URL`, `MULTIPART_URL`, `HEADER_INJECTION`, `FEED_RSS`, `CLOUD_STORAGE`, `OAUTH_REDIRECT`, `SAML_ACS`, `SSRF_VIA_DNS`, `CRLF_INJECTION`, and more.

The `vuln_type` is included in every JSON and SARIF finding — giving the operator precise attack-surface context beyond "this is SSRF."

---

## Components

| Module | Role |
|--------|------|
| `main.py` | CLI entry point — argument parsing, config loading, `--review` mode runner |
| `core/agent.py` | Core orchestrator — 10-phase pipeline, concurrent worker pool, pivot hop loop |
| `core/authorized_action_gate.py` | Governance gate — `FindingProposal` lifecycle, operator approval, `run_authorized_evidence()` |
| `core/cli_review.py` | Interactive terminal UI for reviewing pending action proposals (`--review`) |
| `core/path_probe.py` | Predictable path wordlist probe — 75+ SSRF-prone paths, HEAD/GET, candidate generation |
| `core/file_upload_probe.py` | File upload SSRF detection — SVG, DOCX, XML external references, in-band heuristics |
| `core/vuln_classifier.py` | 25-category SSRF vulnerability type classifier — post-prescore, pre-context-classifier |
| `core/payload_loader.py` | Cached JSON payload file loader for `core/payloads/` |
| `core/crawler.py` | Native BFS crawler — form parsing, static JS analysis, headless Playwright escalation, robots/sitemap/security.txt seeding |
| `core/spider_adapter.py` | Converts Hellhound Spider JSON or flat arrays into scored `Candidate` objects |
| `core/prescore.py` | Phase 00 — relevance scoring and triage queue ordering |
| `core/baseline.py` | Phase 01 — 5-sample baseline profiling, infra-noise tracking, auth-redirect detection |
| `core/context_classifier.py` | Phase 02 — parameter context classification into 6 SSRF context classes |
| `core/waf_detector.py` | Phase 03 — 11 WAF vendor fingerprinting with adaptive evasion mutation chains |
| `core/differential.py` | Phase 04 — z-score statistical anomaly engine; URL reflection detection |
| `core/oob_hub.py` | Phase 05 — Interactsh OOB token lifecycle, background poll loop, incremental tick polling |
| `core/evidence_engine.py` | Phase 06 — cloud metadata, Kubernetes API, Redis/Memcached, file-read; gated by `AuthorizedActionGate` |
| `core/chaining.py` | Phase 07 — second-order SSRF pivot extraction, DNS rebinding detection |
| `core/scoring.py` | Phase 08 — confidence tier assignment and reduction cap enforcement |
| `core/reporter.py` | Phase 09 — JSON + SARIF 2.1.0 generation, `curl` PoC builder, finding deduplication |
| `core/feedback.py` | Phase 10 — cross-candidate pattern propagation, WAF chain caching, IMDSv2 escalation |
| `core/http_client.py` | Async HTTP engine with rate limiting, proxy support, redirect handling |
| `core/models.py` | Core data models — `Candidate`, `ProbeResult`, `FindingProposal`, `ScanReport`, `VulnType`, etc. |
| `core/payload_engine.py` | SSRF payload construction — Gopher, Dict, cloud metadata URLs, mutation chains |
| `core/auth_manager.py` | Auth injection — Bearer, Cookie, API key; spider header auto-detection |
| `core/loader.py` | Input file ingestion — Spider JSON and flat candidate array format parsing |
| `core/console.py` | Terminal UI — cyber tactical HUD, phase headers, status board, colour system |
| `core/known_exploits.py` | Known-exploit registry — CVE escalation rules for internal services and cloud APIs |
| `core/openapi_adapter.py` | OpenAPI/Swagger spec auto-discovery and candidate generation |
| `core/graphql_adapter.py` | GraphQL introspection-based SSRF surface extraction |
| `core/dns_intel.py` | DNS intelligence gathering — A/AAAA/CNAME/MX/TXT resolution for rebinding/pivot analysis |
| `core/js_intel.py` | Static JS analysis — `fetch`/`axios`/`XHR` string-literal extraction |
| `core/recon_quality.py` | Crawler output quality gate — soft-404/bot-block/duplicate-shell filtering |
| `core/wayback_probe.py` | Wayback Machine historical endpoint seeding |
| `core/subdomain_enum.py` | Subdomain enumeration via crt.sh Certificate Transparency |
| `core/spa_detector.py` | SPA framework detection — React, Angular, Vue, Next.js |
| `core/payloads/` | JSON payload files: `contextual_payloads.json`, `ssrf_paths.json`, `cloud_metadata.json`, `waf_signatures.json`, `known_exploitable_services.json` |
| `install.sh` | Installer — creates `.venv`, installs dependencies, deploys global `crossforge` command |

---

## CLI Reference

```
crossforge [OPTIONS] <target_url>
crossforge --input <spiderfile.json> [target_url] [OPTIONS]
crossforge --review <report.json>

Governance & Review:
  --review REPORT_JSON    Interactive review of pending action proposals from a prior scan

Authentication:
  --bearer TOKEN          Bearer/JWT token injected into every request
  --api-key KEY           API key value
  --api-key-header HDR    Header name for --api-key (default: X-Api-Key)
  --cookie NAME=VALUE     Session cookie (repeatable: --cookie a=b --cookie c=d)

OOB:
  --oob URL               Interactsh server URL for blind SSRF confirmation
                          Without OOB, findings cap at TENTATIVE tier.

Crawl & Recon (when --input is omitted):
  --crawl-depth N         BFS max depth (default: 5)
  --crawl-max-pages N     Starting page budget (default: 40, ceiling: 400)
  --crawl-scope HOST      Extra in-scope host (repeatable)
  --no-crawl-js           Disable static JS endpoint extraction

Scan Control:
  --mode MODE             detect (default) | detect_exploit
  --rate N                Requests per second (default: 20)
  --timeout N             Per-request timeout in seconds (default: 10)
  --max-hops N            SSRF chain depth limit (default: 3)
  --no-openapi            Disable OpenAPI/Swagger auto-discovery
  --proxy URL             HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)
  --config PATH           Path to config.yaml (default: ./core/config.yaml)

Output:
  --output DIR            Report output directory (default: ./reports)
  --verbose               Show all candidates including clean/skipped
  --quiet                 Suppress banner and status board (findings only)
```

---

## Configuration (`core/config.yaml`)

Key sections:

```yaml
scan_mode: detect          # detect | detect_exploit

scan:
  concurrency: 10          # candidates in-flight simultaneously (OOB cycles overlap)

path_probe:
  enabled: true
  concurrency: 10
  timeout: 5.0
  max_candidates: 300      # prevents queue explosion on large targets

file_upload_probe:
  enabled: true
  file_types: [svg, docx, xml]

graphql:
  enabled: true
  timeout: 8.0

crawl:
  max_pages_floor: 40
  max_pages_ceiling: 400
  max_depth: 5
  headless_enabled: true   # Playwright escalation for SPAs (requires playwright)
  quality_gate_enabled: true
  subdomain_enum_enabled: false   # opt-in: queries crt.sh
  wayback_enabled: false          # opt-in: third-party dependency

oob:
  server_url: null         # e.g. "https://oast.pro"
  poll_interval: 5.0

evidence:
  aggressive: false        # dead flag — now gated by AuthorizedActionGate
```

---

## Requirements

```
httpx[http2]>=0.27.0
PyYAML>=6.0.1
rich>=13.7.1

# Optional — headless SPA rendering
# pip install playwright && playwright install chromium

# Optional — full DNS record enumeration (CNAME/MX/TXT/NS)
# pip install dnspython
```

---

## Output Files

After a scan, CrossForge writes to `./reports/` (or `--output DIR`):

| File | Format | Description |
|------|--------|-------------|
| `crossforge_report.json` | JSON | Full scan report — findings, pending proposals, authorized action log, skipped candidates |
| `crossforge_report.sarif` | SARIF 2.1.0 | CI/CD-importable findings — compatible with GitHub Advanced Security, VS Code, etc. |
| `evidence/` | Per-finding files | Raw evidence artifacts from authorized evidence collection |

---

## Legal

CrossForge must only be used against systems you are **explicitly authorized to test**. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction.

> This tool is intended solely for authorized security assessments, red-team engagements, and security research.

---

<p align="center">
  Built by <b>Hellhound Security</b> &nbsp;·&nbsp; Part of the <a href="https://github.com/project-hellhound-org">Project Hellhound</a> toolkit
</p>
