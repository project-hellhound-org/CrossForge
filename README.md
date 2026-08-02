<p align="center">
  <img src="photo_2026-07-17_18-59-11.jpg" alt="CrossForge" width="650"/>
</p>

<h1 align="center">CrossForge</h1>
<h3 align="center">Autonomous SSRF Detection · Exploit · Verify Agent</h3>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-1.1.0-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/evasion-WAF--Adaptive-critical?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square"/>
</p>

<p align="center">
  <b>10-Phase Pipeline &nbsp;·&nbsp; Differential Probing &nbsp;·&nbsp; Authorized Action Gate &nbsp;·&nbsp; OOB-Verified &nbsp;·&nbsp; Zero False Positives</b>
</p>

---

## Overview

CrossForge is an enterprise-grade autonomous SSRF (Server-Side Request Forgery) detection, exploitation, and verification agent built for modern web targets. It pairs a SPA-aware native crawler, wordlist-based predictable path discovery, and file-upload SSRF probing with a 10-phase detection pipeline. 

CrossForge incorporates a strict **Authorized Action Gate** governance system — ensuring evidence collection and active pivots into internal networks require explicit operator authorization, reviewable via CLI interactive proposal approval (`--review`).

Every finding is verified via differential z-score analysis or out-of-band callback confirmation, timestamped, and delivered with a ready-to-run `curl` PoC, pending action proposals, and SARIF 2.1.0 report artifacts.

---

## Features

- **10-Phase Autonomous Pipeline** — Surface Triage → Baseline → Context Classify → WAF Fingerprint → Differential Probe → OOB Correlation → Authorized Action Gate & Evidence Engine → Chain/Pivot → Confidence Score → Adaptive Feedback
- **Predictable Path Discovery (`core/path_probe.py`)** — Wordlist-based recon probing for unlisted, framework-standard, and hidden SSRF-prone endpoints
- **File Upload SSRF Probe (`core/file_upload_probe.py`)** — Detects SSRF vectors inside uploaded SVG (`<image>`, `<use>`), OOXML (`DOCX` relationships), and XML (`XXE SYSTEM`) payloads
- **Authorized Action Gate (`core/authorized_action_gate.py`)** — Hard governance stop between Phase 4 detection and internal service data extraction/pivoting
- **Interactive Proposal Review (`--review`)** — CLI interactive workflow to inspect, approve, or decline pending action proposals serialized in scan reports
- **Native BFS Crawler** — Read-only crawl with static JS analysis (`fetch`/`axios`/`XHR`), form parsing, and OpenAPI/GraphQL auto-discovery
- **Differential Probing** — z-score anomaly detection on timing, content-length, redirect depth, and status code (capped at `10.0` with a 2-dimension noise floor)
- **OOB Blind SSRF Confirmation** — Per-candidate Interactsh tokens; async pattern detection for FIRM-tier findings without guessing
- **Evidence Engine** — Cloud IMDS (AWS/GCP/Azure), Kubernetes API, ECS Metadata, Oracle Cloud, Redis/Memcached banner, file read — schema-matched artifact extraction for CERTAIN-tier confirmation
- **WAF Fingerprinting & Evasion** — 11 vendor signatures with per-vendor adaptive mutation chains
- **Chain / Pivot Detection** — Second-order SSRF, DNS rebinding detection, K8s/ECS lateral pivot, up to `max_hops=3` depth
- **Confidence Scoring System** — 4-tier confidence model (`TENTATIVE` → `FIRM` → `CERTAIN` → `CRITICAL+`) with known-exploit escalation
- **Structured Reporting** — JSON + SARIF 2.1.0 output; `curl` PoC per finding; action proposals serialization

---

## Installation

```bash
git clone https://github.com/project-hellhound-org/CrossForge.git crossforge
cd crossforge
chmod +x install.sh
./install.sh
```

Requires Python 3.10+. Creates an isolated `.venv` and links `crossforge` globally via `/usr/local/bin/crossforge`.

```bash
# Manual install (development editable mode)
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Verify installation
python3 main.py --version
```

---

## Usage

```bash
# Basic detect scan from Hellhound Spider JSON file
python3 main.py --input spider_output.json http://target.com

# No spider file — CrossForge crawls target & probes predictable paths
python3 main.py http://target.com

# With OOB for blind SSRF confirmation (FIRM tier findings)
python3 main.py --input spider.json --oob https://oast.pro

# Authenticated scan — Bearer token (JWT)
python3 main.py --input spider.json --bearer eyJhbGciOiJIUzI1NiJ9...

# Full pentest: OOB + auth + Burp proxy intercept
python3 main.py --input spider.json \
           --oob https://oast.pro \
           --bearer eyJhbGciOiJIUzI1NiJ9... \
           --proxy http://127.0.0.1:8080

# Interactive CLI Review of pending action proposals from a prior scan
python3 main.py --review ./reports/report.json

# Exploit mode — unlocks Gopher/Dict protocol probing (requires YES acknowledgment)
python3 main.py --input spider.json --mode detect_exploit
```

---

## Input Formats

CrossForge supports three input modes that all converge on the same triage and filter pipeline:

| Mode | Flag | Description |
|------|------|-------------|
| **Spider JSON** (recommended) | `--input spider.json` | Output from [Hellhound Spider](https://github.com/project-hellhound-org/X5Sentry). Auto-detected by `endpoints` + `meta` keys. Provides full surface coverage. |
| **Flat Candidate Array** | `--input candidates.json` | JSON array of explicit candidate objects. Each entry requires `url`, `method`, `parameter`, `location`. |
| **Native Crawl & Path Discovery** | *(no `--input`)* | Provide a target URL only. CrossForge crawls the target via BFS, form parsing, static JS analysis, and wordlist path probing — then feeds discovery through the same pipeline. |

---

## 10-Phase Pipeline

| Phase | Name | What it does |
|-------|------|-------------|
| `00` | **Surface Triage** | Pre-score candidates HIGH/MEDIUM/LOW via `prescore.py`; drop zero-score entries before I/O |
| `01` | **Baseline & Recon** | 5 clean samples per candidate; infra-noise detection; predictable path discovery (`path_probe.py`) |
| `02` | **Context Classifier** | Classify candidates: `fetch_url` / `redirect` / `file_include` / `crlf_injection` / `host_header` / `file_upload` |
| `03` | **WAF Fingerprint** | 11 vendor signatures; score-based matching; per-vendor adaptive mutation chains via `waf_detector.py` |
| `04` | **Differential Probe** | z-score anomaly on timing, redirect depth, status code, content-length (cap 10.0, 2-dim floor) |
| `05` | **OOB Correlation** | Per-candidate Interactsh token injection; async callback polling; DNS/HTTP pattern matching |
| `06` | **Authorized Gate & Evidence** | Enforces action permits; Cloud IMDS, K8s API, ECS, Oracle Cloud, Redis/Memcached, file read |
| `07` | **Chain / Pivot** | Second-order SSRF; DNS rebinding detection; K8s/ECS lateral pivot; `max_hops=3` recursion |
| `08` | **Confidence Scoring** | Known-exploit registry escalation; reduction caps; per-candidate final tier assignment |
| `09` | **Reporter & Proposals** | JSON report + SARIF 2.1.0; pending action proposals serialization; `curl` PoC per finding |
| `10` | **Adaptive Feedback** | Pattern propagation across candidates; WAF chain caching; IMDSv2 token escalation |

---

## Confidence Tiers

| Tier | Signal | CVSS | Severity |
|------|--------|------|----------|
| `TENTATIVE` | Differential anomaly detected — no external confirmation | 4.3 | Medium |
| `FIRM` | OOB callback confirmed — server made outbound request | 6.5 | High |
| `CERTAIN` | Schema-matched evidence artifact (IMDS body, Redis banner, K8s version) | 8.6 | Critical |
| `CRITICAL+` | Chained SSRF, K8s API access, or known-exploitable internal service reached | 9.6 | Critical |

---

## Scan Modes

| Mode | Flag | Description |
|------|------|-------------|
| `detect` | *(default)* | Read-only detection. Safe for production targets. All 10 phases active with Authorized Action Gate gating evidence/pivots. |
| `detect_exploit` | `--mode detect_exploit` | Unlocks Gopher/Dict protocol banner probing. Still read-only. Requires operator `YES` acknowledgment at runtime. **Pentest-only.** |

---

## Components

| Module | Role |
|--------|------|
| `main.py` | CLI entry point — argument parsing, config loading, `--review` mode runner |
| `core/agent.py` | Core orchestrator — 10-phase pipeline runner with per-phase console output |
| `core/authorized_action_gate.py` | Governance gate managing action proposals and internal execution permits |
| `core/cli_review.py` | Interactive terminal UI for reviewing pending action proposals from reports |
| `core/path_probe.py` | Predictable path wordlist probe for hidden SSRF endpoint discovery |
| `core/file_upload_probe.py` | File upload SSRF detection (SVG, DOCX, XML external references) |
| `core/crawler.py` | Native BFS crawler — BFS, form parsing, JS static analysis, sitemap/robots.txt |
| `core/spider_adapter.py` | Converts Hellhound Spider JSON or flat arrays into scored `Candidate` objects |
| `core/prescore.py` | Phase 00 — relevance scoring and triage queue ordering |
| `core/baseline.py` | Phase 01 — baseline profiling, infra-noise tracking, auth-redirect detection |
| `core/context_classifier.py` | Phase 02 — parameter context classification into 6 SSRF context classes |
| `core/waf_detector.py` | Phase 03 — 11 WAF vendor fingerprinting with adaptive evasion mutation chains |
| `core/differential.py` | Phase 04 — z-score statistical anomaly probing engine |
| `core/oob_hub.py` | Phase 05 — Interactsh OOB token lifecycle management and async polling |
| `core/evidence_engine.py` | Phase 06 — cloud metadata, Kubernetes API, Redis/Memcached, file-read extraction |
| `core/chaining.py` | Phase 07 — second-order SSRF pivot, DNS rebinding detection |
| `core/scoring.py` | Phase 08 — confidence tier assignment and reduction cap enforcement |
| `core/reporter.py` | Phase 09 — JSON + SARIF 2.1.0 report generation and `curl` PoC builder |
| `core/feedback.py` | Phase 10 — cross-candidate pattern propagation and adaptive chain caching |
| `core/http_client.py` | Async HTTP engine with rate limiting, proxy support, redirect handling |
| `core/models.py` | Core data models — `Candidate`, `ProbeResult`, `FindingProposal`, `ScanReport`, etc. |
| `core/payload_engine.py` | SSRF payload construction — Gopher, Dict, cloud metadata URLs, mutation chains |
| `core/auth_manager.py` | Authentication injection — Bearer, Cookie, API key; spider header auto-detection |
| `core/loader.py` | Input file ingestion — Spider JSON and flat candidate array format parsing |
| `core/console.py` | Terminal UI — Cyber Tactical HUD, phase headers, status board, colour system |
| `core/known_exploits.py` | Known-exploit registry — escalation rules for internal services and cloud APIs |
| `core/openapi_adapter.py` | OpenAPI/Swagger spec auto-discovery and candidate generation |
| `core/graphql_adapter.py` | GraphQL introspection-based SSRF surface extraction |
| `core/dns_intel.py` | DNS intelligence gathering for rebinding and pivot analysis |
| `core/js_intel.py` | Static JS analysis — `fetch`/`axios`/`XHR` string literal extraction |
| `core/recon_quality.py` | Crawler output quality scoring and coverage gap detection |
| `core/wayback_probe.py` | Wayback Machine historical endpoint discovery |
| `core/subdomain_enum.py` | Subdomain enumeration for crawl scope expansion |
| `core/spa_detector.py` | SPA framework detection — React, Angular, Vue, Next.js |
| `core/vuln_classifier.py` | Post-probe vulnerability classification and severity mapping |
| `install.sh` | High-fidelity installer — creates `.venv`, installs deps, deploys global command |

---

## CLI Reference

```
crossforge [OPTIONS] <target_url>
crossforge --input <spiderfile.json> [target_url] [OPTIONS]
crossforge --review <report.json>

Governance & Review:
  --review REPORT_JSON    Review pending action proposals from a prior scan's report.json

Authentication:
  --bearer TOKEN          Bearer/JWT token injected into every request
  --api-key KEY           API key value
  --api-key-header HDR    Header name for --api-key (default: X-Api-Key)
  --cookie NAME=VALUE     Session cookie (repeatable)

OOB:
  --oob URL               Interactsh server for blind SSRF confirmation

Crawl & Recon (when --input is omitted):
  --crawl-depth N         BFS max depth (default: 5)
  --crawl-max-pages N     Page budget (default: 40, ceiling: 400)
  --crawl-scope HOST      Extra in-scope host (repeatable)
  --no-crawl-js           Disable static JS analysis

Scan Control:
  --mode MODE             detect (default) | detect_exploit
  --rate N                Requests per second (default: 20)
  --timeout N             Per-request timeout in seconds (default: 10)
  --max-hops N            SSRF chain depth limit (default: 3)
  --no-openapi            Disable OpenAPI/Swagger auto-discovery
  --proxy URL             HTTP proxy (e.g. http://127.0.0.1:8080)
  --config PATH           Path to config.yaml (default: ./core/config.yaml)

Output:
  --output DIR            Report directory (default: ./reports)
  --verbose               Show all candidates including clean/skipped
  --quiet                 Suppress banner and status board
```

---

## Requirements

```
httpx[http2]>=0.27.0
PyYAML>=6.0.1
rich>=13.7.1

# Optional — headless rendering for SPA targets
playwright>=1.44.0
```

---

## Legal

CrossForge must only be used against systems you are **explicitly authorized to test**. Unauthorized use may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction.

> This tool is intended solely for authorized security assessments, red-team engagements, and security research.

---

<p align="center">
  Built by <b>Hellhound Security</b> &nbsp;·&nbsp; Part of the <a href="https://github.com/project-hellhound-org">Project Hellhound</a> toolkit
</p>
