"""
CrossForge SSRF Detection Agent — CLI Entry Point
===================================================
Usage:
  crossforge [OPTIONS] <target_url>
  crossforge [OPTIONS] --input <spiderfile.json>
  crossforge [OPTIONS] --input <spiderfile.json> <target_url>
  crossforge --help
  crossforge --version

Examples:
  crossforge --input spider.json http://localhost:5000
  crossforge --input candidates.json --oob https://oast.pro --bearer eyJhb...
  crossforge --input spider.json --mode detect_exploit --proxy http://127.0.0.1:8080
  crossforge --input spider.json --rate 15 --timeout 12 --output /tmp/results
"""

from __future__ import annotations
import argparse
import asyncio
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from core.console import (
    C, color, section, info, warn, err, ok, tprint, configure
)

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
   ______                 ______
  / ____/________  _____ / ____/___  _________ ____
 / /   / ___/ __ \/ ___// /_  / __ \/ ___/ __ `/ _ \
/ /___/ /  / /_/ (__  )/ __/ / /_/ / /  / /_/ /  __/
\____/_/   \____/____/_/     \____/_/   \__, /\___/
                                        /____/
"""

VERSION = "1.0.0"
TAGLINE = "Enterprise SSRF Detection · Exploit · Verify"


def print_banner(mode: str = "DETECT") -> None:
    mode_col = C.BRED if "EXPLOIT" in mode.upper() else C.BCYAN
    tprint(color(BANNER, C.BRED + C.BOLD))
    tprint(f"  {color('CrossForge', C.BRED + C.BOLD)} {color('SSRF Agent', C.BWHITE)}  "
           f"{color('v' + VERSION, C.DIM)}   "
           f"{color(TAGLINE, C.DIM)}")
    tprint(f"  Mode: {color(mode.upper(), mode_col, C.BOLD)}\n")


# ─────────────────────────────────────────────────────────────────────────────
# HELP
# ─────────────────────────────────────────────────────────────────────────────

HELP_TEXT = f"""
{color('CrossForge SSRF Agent v' + VERSION, C.BRED + C.BOLD)}
{color('─' * 70, C.DIM)}

{color('DESCRIPTION', C.BWHITE + C.BOLD)}
  CrossForge is an enterprise-grade autonomous SSRF detection and verification
  agent. It runs a 10-phase pipeline — surface triage, baseline establishment,
  context classification, WAF fingerprinting, differential probing, OOB
  correlation, evidence collection, chain pivoting, confidence scoring, and
  adaptive feedback — against every SSRF-plausible parameter on the target.

{color('USAGE', C.BWHITE + C.BOLD)}
  crossforge [OPTIONS] <target_url>
  crossforge --input <spiderfile.json> [target_url] [OPTIONS]

{color('INPUT FORMATS', C.BWHITE + C.BOLD)}
  {color('Spider JSON  (FORMAT B, recommended)', C.BYELLOW)}
    Output from the Hellhound Spider tool. Auto-detected by the presence
    of "endpoints" + "meta" keys. Provides full surface coverage.
    Example: crossforge --input spider_localhost_5000.json http://target.com

  {color('Flat candidate array  (FORMAT A)', C.BYELLOW)}
    A JSON array of explicit candidate objects. Each entry requires:
    url, method, parameter, location (query|body_json|body_form|header|cookie|path).
    Example: crossforge --input webhooks.json

  {color('No --input — Native Crawl  (FORMAT C)', C.BYELLOW)}
    No spider file? Give CrossForge just a target URL and it crawls the
    site itself (BFS, form parsing, static JS analysis for SPA API
    calls) then feeds the discovery through the SAME triage/filter
    pipeline a supplied spider file gets. See --crawl-* flags below.
    Example: crossforge http://target.com

{color('SCAN MODES', C.BWHITE + C.BOLD)}
  {color('detect          (DEFAULT)', C.BGREEN)}
    Read-only detection. Safe for production targets. Runs all 10 phases
    but restricts evidence collection to non-destructive operations only
    (Redis INFO read, /etc/hostname read, cloud metadata schema matching).

  {color('detect_exploit  (PENTEST ONLY)', C.BRED)}
    Unlocks Gopher/Dict protocol banner probing (still read-only).
    Requires explicit operator acknowledgment (type YES at the prompt).
    Use only on targets you are authorized to test.

{color('AUTHENTICATION OPTIONS', C.BWHITE + C.BOLD)}
  --bearer TOKEN        JWT or opaque Bearer token injected into every request.
                        Auto-detected from spider headers if present.
  --api-key KEY         API key value for authenticated scanning.
  --api-key-header HDR  Header name for --api-key (default: X-Api-Key).
  --cookie NAME=VALUE   Session cookie. Can be specified multiple times.

{color('OOB (OUT-OF-BAND) OPTIONS', C.BWHITE + C.BOLD)}
  --oob URL             Interactsh server URL for blind SSRF confirmation.
                        Without OOB, findings cap at TENTATIVE tier.
                        Example: --oob https://oast.pro
                        Self-hosted: --oob https://interactsh.example.internal

{color('RECON / CRAWL OPTIONS (only used when --input is omitted)', C.BWHITE + C.BOLD)}
  --crawl-depth N        Max BFS depth (default: 5)
  --crawl-max-pages N    Starting page budget; adapts upward on high yield
                        (default: 40, hard ceiling 400 unless raised)
  --crawl-scope HOST     Extra in-scope host, e.g. an API subdomain.
                        Repeatable: --crawl-scope api.target.com
  --no-crawl-js          Disable static JS analysis (fetch/axios/XHR
                        string-literal extraction from linked/inline JS)

{color('SCAN CONTROL', C.BWHITE + C.BOLD)}
  --mode MODE           detect (default) | detect_exploit
  --rate N              Requests per second (default: 20)
  --timeout N           Per-request timeout in seconds (default: 10)
  --max-hops N          SSRF chain depth limit (default: 3)
  --no-openapi          Disable OpenAPI/Swagger spec auto-discovery
  --proxy URL           HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)
  --config PATH         Path to config.yaml (default: ./core/config.yaml)

{color('OUTPUT OPTIONS', C.BWHITE + C.BOLD)}
  --output DIR          Report output directory (default: ./reports)
  --verbose             Show all candidates including clean/skipped ones
  --quiet               Suppress banner and status board, findings only

{color('CONFIDENCE TIERS', C.BWHITE + C.BOLD)}
  {color('TENTATIVE', C.BCYAN)}     Differential anomaly detected. Needs manual review.
  {color('FIRM',      C.BYELLOW)}   OOB callback confirmed — server made outbound request.
  {color('CERTAIN',   C.BRED)}      Schema-matched evidence artifact (IMDS, Redis banner…).
  {color('CRITICAL+', C.BRED + C.BOLD)} Chained SSRF, K8s API, or known-exploitable service reached.

{color('PIPELINE PHASES', C.BWHITE + C.BOLD)}
  Phase 00 · Surface Triage       Pre-score all candidates HIGH/MEDIUM/LOW
  Phase 01 · Baseline Collection  5 clean samples per candidate; infra-noise detection
  Phase 02 · Context Classifier   fetch_url / redirect / file_include / crlf / host_header
  Phase 03 · WAF Fingerprint      11 vendors; per-vendor mutation chains
  Phase 04 · Differential Probe   z-score anomaly on timing, redirect, status, content-length
  Phase 05 · OOB Correlation      Interactsh token-per-candidate; async pattern detection
  Phase 06 · Evidence Engine      Cloud IMDS, K8s API, Redis/Memcached banner, file read
  Phase 07 · Chain / Pivot        Second-order SSRF; DNS rebinding; max_hops=3
  Phase 08 · Confidence Scoring   Known-exploit escalation; confidence-reduction caps
  Phase 09 · Reporter             JSON + SARIF 2.1.0; curl PoC per finding
  Phase 10 · Adaptive Feedback    Pattern propagation; WAF chain caching; IMDSv2 escalation

{color('EXAMPLES', C.BWHITE + C.BOLD)}
  # Basic detect scan from spider file
  crossforge --input spider.json http://target.com

  # No spider file — CrossForge crawls the target itself
  crossforge http://target.com --oob https://oast.pro

  # Native crawl scoped to an extra API subdomain, deeper BFS
  crossforge http://target.com --crawl-scope api.target.com --crawl-depth 8

  # Full pentest: OOB + auth + Burp proxy intercept
  crossforge --input spider.json --oob https://oast.pro \\
             --bearer eyJhbGciOiJIUzI1NiJ9.xxx \\
             --proxy http://127.0.0.1:8080

  # Exploit mode with API key auth
  crossforge --input spider.json --mode detect_exploit \\
             --api-key sk-abc123 --api-key-header X-Api-Key

  # Quiet mode for CI/CD pipeline
  crossforge --input candidates.json --quiet --output /tmp/crossforge-ci

  # Verbose mode to see all candidate decisions
  crossforge --input spider.json --verbose

{color('─' * 70, C.DIM)}
{color('IMPORTANT', C.BYELLOW + C.BOLD)}: CrossForge must only be used against systems you are explicitly
authorized to test. Unauthorized use may violate computer fraud laws.
"""


def print_help() -> None:
    tprint(HELP_TEXT)


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crossforge",
        description="CrossForge SSRF Detection Agent",
        add_help=False,
    )
    p.add_argument("target",         nargs="?",   default=None, help="Target base URL")
    p.add_argument("--input",        "-i",        required=False, metavar="FILE",
                   help="Candidate file (Spider JSON or flat array JSON)")
    p.add_argument("--mode",                      default=None,
                   choices=["detect", "detect_exploit"],
                   help="Scan mode (detect | detect_exploit)")
    p.add_argument("--bearer",                    default=None,  metavar="TOKEN")
    p.add_argument("--api-key",      dest="api_key", default=None, metavar="KEY")
    p.add_argument("--api-key-header", dest="api_key_header", default="X-Api-Key")
    p.add_argument("--cookie",                    action="append", default=[],
                   metavar="NAME=VALUE",
                   help="Session cookie (repeatable: --cookie a=b --cookie c=d)")
    p.add_argument("--oob",                       default=None,  metavar="URL",
                   help="Interactsh server URL")
    p.add_argument("--proxy",                     default=None,  metavar="URL")
    p.add_argument("--rate",         type=float,  default=None,  metavar="N",
                   help="Requests per second (default 20)")
    p.add_argument("--timeout",      type=float,  default=None,  metavar="N",
                   help="Request timeout in seconds (default 10)")
    p.add_argument("--max-hops",     dest="max_hops", type=int, default=None,
                   metavar="N", help="SSRF chain depth limit (default 3)")
    p.add_argument("--no-openapi",   action="store_true", default=False)
    p.add_argument("--crawl-depth",     dest="crawl_depth", type=int, default=None,
                   metavar="N", help="Native crawler max BFS depth (default: 5)")
    p.add_argument("--crawl-max-pages", dest="crawl_max_pages", type=int, default=None,
                   metavar="N", help="Native crawler starting page budget (default: 40)")
    p.add_argument("--crawl-scope",     dest="crawl_scope", action="append", default=[],
                   metavar="HOST", help="Extra in-scope host for the native crawler (repeatable)")
    p.add_argument("--no-crawl-js",     dest="no_crawl_js", action="store_true", default=False,
                   help="Disable native crawler's static JS endpoint extraction")
    p.add_argument("--config",                    default=None,  metavar="PATH")
    p.add_argument("--output",       "-o",        default=None,  metavar="DIR")
    p.add_argument("--verbose",      "-v",        action="store_true", default=False)
    p.add_argument("--quiet",        "-q",        action="store_true", default=False)
    p.add_argument("--version",                   action="store_true", default=False)
    p.add_argument("--help",         "-h",        action="store_true", default=False)
    return p


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG PATCHING
# ─────────────────────────────────────────────────────────────────────────────

def patch_config(cfg: dict, args: argparse.Namespace) -> dict:
    if args.mode:
        cfg["scan_mode"] = args.mode
    if args.proxy:
        cfg.setdefault("http", {})["proxy"] = args.proxy
    if args.timeout:
        cfg.setdefault("http", {})["timeout"] = args.timeout
    if args.oob:
        cfg.setdefault("oob", {})["server_url"] = args.oob
    if args.bearer:
        cfg.setdefault("auth", {})["bearer_token"] = args.bearer
    if args.api_key:
        cfg.setdefault("auth", {})["api_key"]        = args.api_key
        cfg.setdefault("auth", {})["api_key_header"]  = args.api_key_header
    if args.cookie:
        cookies: dict = {}
        for raw in args.cookie:
            if "=" in raw:
                k, _, v = raw.partition("=")
                cookies[k.strip()] = v.strip()
        cfg.setdefault("auth", {})["cookies"] = cookies
    if args.no_openapi:
        cfg.setdefault("openapi", {})["enabled"] = False
    if args.crawl_depth is not None:
        cfg.setdefault("crawl", {})["max_depth"] = args.crawl_depth
    if args.crawl_max_pages is not None:
        cfg.setdefault("crawl", {})["max_pages_floor"] = args.crawl_max_pages
    if args.crawl_scope:
        cfg.setdefault("crawl", {})["extra_scope_hosts"] = args.crawl_scope
    if args.no_crawl_js:
        cfg.setdefault("crawl", {})["js_static_analysis"] = False
    if args.output:
        cfg.setdefault("output", {})["dir"] = args.output
    if args.rate:
        cfg.setdefault("rate_limit", {})["requests_per_second"] = args.rate
    if args.max_hops is not None:
        cfg.setdefault("chaining", {})["max_hops"] = args.max_hops
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT ACK PROMPT
# ─────────────────────────────────────────────────────────────────────────────

_EXPLOIT_ACK = """
  {yellow}╔══════════════════════════════════════════════════════════════╗{reset}
  {yellow}║{reset}  {bold}DETECT + EXPLOIT MODE — OPERATOR ACKNOWLEDGMENT REQUIRED{reset}  {yellow}║{reset}
  {yellow}╠══════════════════════════════════════════════════════════════╣{reset}
  {yellow}║{reset}  This mode enables Gopher/Dict protocol interaction modules. {yellow}║{reset}
  {yellow}║{reset}  All probes remain READ-ONLY — no FLUSHALL, no crontab, no  {yellow}║{reset}
  {yellow}║{reset}  reverse shells. Banner/INFO reads only.                     {yellow}║{reset}
  {yellow}║{reset}                                                              {yellow}║{reset}
  {yellow}║{reset}  You confirm this scan is FULLY AUTHORISED against target.   {yellow}║{reset}
  {yellow}╚══════════════════════════════════════════════════════════════╝{reset}

  Type {bold}YES{reset} to continue, anything else to abort: """

def exploit_ack(no_tty: bool = False) -> bool:
    msg = _EXPLOIT_ACK.format(
        yellow=C.BYELLOW, bold=C.BOLD, reset=C.RESET,
    )
    sys.stdout.write(msg)
    sys.stdout.flush()
    if no_tty:
        return False
    try:
        ans = input()
    except EOFError:
        ans = ""
    return ans.strip().upper() == "YES"


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG SUMMARY BOX
# ─────────────────────────────────────────────────────────────────────────────

def print_config_box(
    mode: str,
    candidates_path: str,
    oob: str,
    proxy: str,
    auth_type: str,
    openapi: bool,
    output: str,
) -> None:
    W = 70
    tprint(f"\n  {color('┌' + '─'*(W-4) + '┐', C.DIM)}")
    rows = [
        ("Mode",       color(mode.upper(),     C.BRED if "EXPLOIT" in mode.upper() else C.BCYAN, C.BOLD)),
        ("Input",      color(candidates_path,  C.BWHITE)),
        ("OOB",        color(oob,              C.BGREEN if oob != "disabled" else C.DIM)),
        ("Auth",       color(auth_type,        C.BGREEN if auth_type != "none" else C.DIM)),
        ("Proxy",      color(proxy,            C.BYELLOW if proxy != "none" else C.DIM)),
        ("OpenAPI",    color("enabled" if openapi else "disabled", C.BCYAN if openapi else C.DIM)),
        ("Output",     color(output,           C.DIM)),
    ]
    for k, v in rows:
        raw_v = v.replace(C.RESET, "").replace(C.BWHITE, "").replace(C.BCYAN, "").replace(C.DIM, "")
        line  = f"  {color('│', C.DIM)}  {color(k+':', C.DIM):<10} {v}"
        raw   = f"  │  {k+':':<10} {raw_v}"
        pad   = max(0, W - 2 - len(raw))
        tprint(line + " " * pad + color("│", C.DIM))
    tprint(f"  {color('└' + '─'*(W-4) + '┘', C.DIM)}\n")


# ─────────────────────────────────────────────────────────────────────────────
# TARGET URL NORMALIZATION
# ─────────────────────────────────────────────────────────────────────────────

# Loopback / RFC1918 private ranges + localhost — overwhelmingly plain HTTP in
# practice (local dev servers, internal lab targets). Defaulting these to
# https:// would silently TLS-handshake-fail against a normal Flask/Django
# dev server, trading one confusing error for another.
_PRIVATE_HOST_RE = re.compile(
    r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost(:|$))",
    re.IGNORECASE,
)


def _normalize_target(raw: str) -> str:
    """
    Handles the two common ways operators mistype a target URL:
      1. "http:127.0.0.1:5000"  (single colon, missing //) — the scheme
         was typed correctly but truncated; repair it rather than treat
         "http:127.0.0.1:5000" as a bare host and double-prefix it into
         "https://http:127.0.0.1:5000" (a real bug this project shipped
         and a real operator hit — fixed here, not papered over).
      2. "127.0.0.1:5000" / "target.com"  (no scheme at all) — prepend one,
         defaulting to http:// for loopback/private targets and https://
         for everything else.
    """
    t = raw.strip()
    m = re.match(r"^(https?):(?!//)(.*)$", t, re.IGNORECASE)
    if m:
        return f"{m.group(1)}://{m.group(2)}"
    if re.match(r"^https?://", t, re.IGNORECASE):
        return t
    scheme = "http" if _PRIVATE_HOST_RE.match(t) else "https"
    return f"{scheme}://{t}"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

async def _run(tmp_config: str, candidates_path: "str | None", target_url: "str | None") -> None:
    from core.agent import CrossForgeAgent
    agent = CrossForgeAgent(tmp_config)
    await agent.run(candidates_path, target_url)


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args   = parser.parse_args(argv)

    # Version
    if args.version:
        print(f"crossforge {VERSION}")
        return

    # Help
    if args.help or (not args.input and not args.target):
        print_banner()
        print_help()
        return

    # Require at least one of --input or a target URL (target-only → native crawl)
    if not args.input and not args.target:
        print_banner()
        err("No input file and no target URL specified.")
        tprint(f"  Use {color('--input <spiderfile.json>', C.BCYAN)}, or give a target URL "
               f"to let CrossForge crawl it itself.")
        tprint(f"  Run {color('crossforge --help', C.BCYAN)} to see all options.")
        sys.exit(1)

    # Configure console
    configure(verbose=args.verbose, quiet=args.quiet)

    # Native-crawl mode needs a fully-qualified URL. See _normalize_target()
    # for exactly which typos this repairs (missing "//", missing scheme).
    if not args.input and args.target:
        args.target = _normalize_target(args.target)
        parsed = urlsplit(args.target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or " " in parsed.netloc:
            print_banner()
            err(f"'{args.target}' doesn't look like a valid target URL.")
            tprint(f"  Expected something like {color('http://target.com', C.BCYAN)} "
                   f"or {color('http://127.0.0.1:5000', C.BCYAN)}")
            sys.exit(1)

    # Load config
    config_path = Path(args.config) if args.config else Path(__file__).parent / "core" / "config.yaml"
    if not config_path.exists():
        err(f"Config file not found: {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    cfg = patch_config(cfg, args)
    mode = cfg.get("scan_mode", "detect")

    # Print banner (unless quiet)
    if not args.quiet:
        print_banner(mode)

    # Exploit mode ack
    if mode == "detect_exploit":
        if not exploit_ack(no_tty=not sys.stdin.isatty()):
            tprint(f"\n  {color('Aborted.', C.BYELLOW)}")
            sys.exit(0)

    # Build auth descriptor
    auth_cfg  = cfg.get("auth", {}) or {}
    auth_desc = (
        "bearer"  if auth_cfg.get("bearer_token") else
        "api_key" if auth_cfg.get("api_key")      else
        "cookies" if auth_cfg.get("cookies")      else
        "none"
    )

    # Config summary
    if not args.quiet:
        input_label = args.input if args.input else f"(native crawl → {args.target})"
        print_config_box(
            mode=mode,
            candidates_path=input_label,
            oob=cfg.get("oob", {}).get("server_url") or "disabled",
            proxy=cfg.get("http", {}).get("proxy")   or "none",
            auth_type=auth_desc,
            openapi=cfg.get("openapi", {}).get("enabled", True),
            output=cfg.get("output", {}).get("dir", "reports"),
        )

    # Write patched config to temp file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump(cfg, tmp)
    tmp.close()

    try:
        asyncio.run(_run(tmp.name, args.input, args.target))
    except KeyboardInterrupt:
        tprint(f"\n  {color('Scan interrupted by operator.', C.BYELLOW)}")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


if __name__ == "__main__":
    main()
