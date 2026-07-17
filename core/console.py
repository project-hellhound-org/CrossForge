"""
CrossForge SSRF Agent — Console Layer
=======================================
Borrowed and extended from LDAPi Detection Agent v15.0 console design.
Provides ANSI-colored phase headers, finding cards, summary boxes, and
the live status board — all thread-safe.
"""

from __future__ import annotations
import re
import sys
import threading
import time
from typing import Optional

_lock = threading.Lock()
_VERBOSE = False
_QUIET   = False


# ---------------------------------------------------------------------------
# ANSI palette
# ---------------------------------------------------------------------------
class C:
    RESET    = "\033[0m";  BOLD     = "\033[1m";  DIM      = "\033[2m"
    RED      = "\033[31m"; GREEN    = "\033[32m"; YELLOW   = "\033[33m"
    BLUE     = "\033[34m"; MAGENTA  = "\033[35m"; CYAN     = "\033[36m"
    WHITE    = "\033[37m"
    BRED     = "\033[91m"; BGREEN   = "\033[92m"; BYELLOW  = "\033[93m"
    BBLUE    = "\033[94m"; BMAGENTA = "\033[95m"; BCYAN    = "\033[96m"
    BWHITE   = "\033[97m"; ORANGE   = "\033[38;5;208m"


def _strip(text: str) -> str:
    """Strip ANSI codes for length calculation."""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def color(text: str, *styles: str) -> str:
    return "".join(styles) + str(text) + C.RESET


def label(tag: str, text: str, tc: str = C.BCYAN) -> str:
    return (f"{color('[', C.DIM)}{color(tag, tc, C.BOLD)}{color(']', C.DIM)} "
            f"{text}")


def tprint(*a, **kw) -> None:
    with _lock:
        print(*a, **kw)


def configure(verbose: bool = False, quiet: bool = False) -> None:
    global _VERBOSE, _QUIET
    _VERBOSE = verbose
    _QUIET   = quiet


# ---------------------------------------------------------------------------
# Semantic print helpers
# ---------------------------------------------------------------------------
def ok(t: str)       -> None: tprint(label("+",       t, C.BGREEN))
def warn(t: str)     -> None: tprint(label("!",       t, C.BYELLOW))
def err(t: str)      -> None: tprint(label("-",       t, C.BRED))
def info(t: str)     -> None: tprint(label("*",       t, C.BCYAN))
def found(t: str)    -> None: tprint(label("FOUND",   t, C.BRED))
def skip(t: str)     -> None:
    if _VERBOSE:
        tprint(label("SKIP",  t, C.DIM))
def vprint(t: str)   -> None:
    if _VERBOSE:
        tprint(label("v",     t, C.DIM))
def dim(t: str)      -> None:
    if not _QUIET:
        tprint(color(f"  {t}", C.DIM))


# ---------------------------------------------------------------------------
# Phase header (LDAPi-style bordered boxes)
# ---------------------------------------------------------------------------
_PHASE_META: dict[int, tuple[str, str, str]] = {
    0:  (C.BBLUE,    "⚡", "SURFACE TRIAGE     "),
    1:  (C.BCYAN,    "📐", "BASELINE COLLECTION"),
    2:  (C.BMAGENTA, "🔎", "CONTEXT CLASSIFIER "),
    3:  (C.ORANGE,   "🛡 ", "WAF FINGERPRINT    "),
    4:  (C.BYELLOW,  "⚠ ", "DIFFERENTIAL PROBE "),
    5:  (C.BRED,     "📡", "OOB CORRELATION    "),
    6:  (C.BRED,     "🔬", "EVIDENCE ENGINE    "),
    7:  (C.BMAGENTA, "🔗", "CHAIN / PIVOT      "),
    8:  (C.BGREEN,   "🏷 ", "CONFIDENCE SCORING "),
    9:  (C.BWHITE,   "📋", "REPORTER           "),
    10: (C.BGREEN,   "🔁", "ADAPTIVE FEEDBACK  "),
}

# ---------------------------------------------------------------------------
# Lifecycle-stage banners (Reconnaissance → Reporting)
# ---------------------------------------------------------------------------
# Deliberately a SEPARATE table/numbering from _PHASE_META above, not a
# replacement for it. _PHASE_META's fine-grained phases (Context Classifier,
# WAF Fingerprint, Differential Probe, OOB, Evidence, Chain/Pivot, Confidence
# Scoring) all run INTERLEAVED per-candidate inside one loop (see
# agent.py::_process_candidate) — there's no point in execution where "WAF
# Fingerprint" is happening for every candidate before "Differential Probe"
# starts for any of them, so a live sequential banner for each would be
# fiction. These 7 lifecycle stages group that same work into the classic
# pentest narrative (Recon/Scan/Enum/Detect/Exploit/Post-Exploit/Report) and
# are printed RETROSPECTIVELY for the interleaved stages (3-6) using stats
# collected during the per-candidate loop, and LIVE for the two stages that
# genuinely do run as sequential full passes (1-2). Retrospective is not
# fabricated — it's an accurate report of what happened, just narrated after
# the fact instead of as a live progress bar.
_LIFECYCLE_META: dict[int, tuple[str, str, str]] = {
    1: (C.BBLUE,    "🔍", "RECONNAISSANCE    "),
    2: (C.BCYAN,    "📡", "SCANNING          "),
    3: (C.BMAGENTA, "🧬", "ENUMERATION       "),
    4: (C.BYELLOW,  "⚠ ", "DETECTION         "),
    5: (C.BRED,     "🔓", "EXPLOITATION      "),
    6: (C.ORANGE,   "🔗", "POST-EXPLOITATION "),
    7: (C.BWHITE,   "📋", "REPORTING         "),
}


def lifecycle_header(stage: int, extra: str = "") -> None:
    """Bordered banner for one of the 7 pentest-lifecycle stages. Same
    visual style as phase_header() but keyed to _LIFECYCLE_META, not
    _PHASE_META — see the module comment above for why these are separate."""
    W = 76
    col, icon, name = _LIFECYCLE_META.get(stage, (C.BCYAN, "▶", "STAGE"))
    inner = f"  {icon}  STAGE {stage} — {name.strip()}  "
    if extra:
        inner += f"({extra})  "
    pad = max(0, W - 2 - len(_strip(inner)))
    lp, rp = pad // 2, pad - pad // 2
    tprint(f"\n{col}╔{'═'*(W-2)}╗{C.RESET}")
    tprint(f"{col}║{C.RESET}{' '*lp}{col}{C.BOLD}{inner}{C.RESET}{col}{' '*rp}║{C.RESET}")
    tprint(f"{col}╚{'═'*(W-2)}╝{C.RESET}")


def lifecycle_result(stage: int, stats: list[tuple[str, str]], width: int = 70) -> None:
    """Summary box for a lifecycle stage — same rendering as phase_result()."""
    col = _LIFECYCLE_META.get(stage, (C.BCYAN,))[0]
    tprint(f"\n{col}┌{'─'*(width-2)}┐{C.RESET}")
    for k, v in stats:
        line = f" {str(k).ljust(30)} │ {str(v)}"
        raw  = _strip(line)
        pad  = max(0, width - 3 - len(raw))
        tprint(f"{col}│{C.RESET}{line}{' '*pad} {col}│{C.RESET}")
    tprint(f"{col}└{'─'*(width-2)}┘{C.RESET}")


def phase_header(number: int, name: str = "", extra: str = "") -> None:
    """Print a bordered phase banner — CrossForge style."""
    W = 76
    col, icon, default_name = _PHASE_META.get(number, (C.BCYAN, "▶", name or "PHASE"))
    display_name = (name or default_name).upper()
    inner = f"  {icon}  PHASE {number:02d} — {display_name}  "
    if extra:
        inner += f"({extra})  "
    pad   = max(0, W - 2 - len(_strip(inner)))
    lp    = pad // 2
    rp    = pad - lp
    tprint(f"\n{col}╔{'═'*(W-2)}╗{C.RESET}")
    tprint(f"{col}║{C.RESET}{' '*lp}{col}{C.BOLD}{inner}{C.RESET}{col}{' '*rp}║{C.RESET}")
    tprint(f"{col}╚{'═'*(W-2)}╝{C.RESET}")


def phase_result(number: int, stats: list[tuple[str, str]], width: int = 70) -> None:
    """Print a summary box after a phase completes."""
    col = _PHASE_META.get(number, (C.BCYAN,))[0]
    tprint(f"\n{col}┌{'─'*(width-2)}┐{C.RESET}")
    for k, v in stats:
        line  = f" {str(k).ljust(30)} │ {str(v)}"
        raw   = _strip(line)
        pad   = max(0, width - 3 - len(raw))
        tprint(f"{col}│{C.RESET}{line}{' '*pad} {col}│{C.RESET}")
    tprint(f"{col}└{'─'*(width-2)}┘{C.RESET}")


def section(title: str) -> None:
    bar = color("─" * 72, C.DIM + C.CYAN)
    tprint(f"\n{bar}")
    tprint(f"  {color(title.upper(), C.BOLD + C.BCYAN)}")
    tprint(f"{bar}")


def progress_bar(cur: int, tot: int, width: int = 30) -> str:
    pct    = cur / tot if tot else 0
    filled = int(pct * width)
    bar    = color("█" * filled, C.BCYAN) + color("░" * (width - filled), C.DIM)
    return f"[{bar}] {color(f'{int(pct*100):3d}%', C.BWHITE)} {color(f'{cur}/{tot}', C.DIM)}"


# ---------------------------------------------------------------------------
# Finding card (per-finding inline structured output)
# ---------------------------------------------------------------------------
_SEVERITY_COLOR = {
    "critical": C.BRED,
    "high":     C.BYELLOW,
    "medium":   C.BCYAN,
    "low":      C.DIM,
    "info":     C.DIM,
}

_TIER_COLOR = {
    "critical_plus": C.BRED,
    "certain":       C.BRED,
    "firm":          C.BYELLOW,
    "tentative":     C.BCYAN,
}


def print_finding_card(finding, idx: int = 0) -> None:
    """Structured inline finding card — clearly readable by any operator."""
    sev_col  = _SEVERITY_COLOR.get(finding.severity.lower(), C.BCYAN)
    tier_col = _TIER_COLOR.get(
        getattr(finding, "confidence_tier", "tentative").lower(), C.BCYAN
    )
    vuln_type = finding.vulnerability_type.replace("_", " ").upper()
    num = color(f"  ╔═══ #{idx:02d} ", C.BRED + C.BOLD) if idx else color("  ╔═══ FINDING ", C.BRED + C.BOLD)

    tprint(f"\n{num}{color(vuln_type, sev_col, C.BOLD)}{color(' ═══', C.BRED + C.BOLD)}")
    tprint(f"  {color('║', C.DIM)} {color('severity :', C.DIM)} {color(finding.severity.upper(), sev_col, C.BOLD):<20}  "
           f"{color('confidence:', C.DIM)} {color(finding.confidence.upper(), tier_col, C.BOLD)}")
    tprint(f"  {color('║', C.DIM)} {color('endpoint :', C.DIM)} {color(finding.target_url, C.BWHITE)}")
    tprint(f"  {color('║', C.DIM)} {color('parameter:', C.DIM)} {color(finding.affected_parameter, sev_col, C.BOLD)}")
    tprint(f"  {color('║', C.DIM)} {color('sub_agent:', C.DIM)} {color(finding.sub_agent, C.DIM)}")

    if finding.cvss_vector:
        tprint(f"  {color('║', C.DIM)} {color('cvss     :', C.DIM)} {color(finding.cvss_vector, C.DIM)}")

    poc = getattr(finding, "proof_of_concept", "") or ""
    if poc:
        tprint(f"  {color('║', C.DIM)} {color('poc      :', C.DIM)} {color(poc[:120], C.BYELLOW)}")

    obs = getattr(finding, "observation", "") or ""
    if obs:
        tprint(f"  {color('║', C.DIM)} {color('signal   :', C.DIM)} {color(obs[:100], C.DIM)}")

    exploit_refs = getattr(finding, "known_exploit_refs", []) or []
    if exploit_refs:
        tprint(f"  {color('║', C.DIM)} {color('exploits :', C.DIM)}", end="")
        for ref in exploit_refs[:2]:
            tprint(f" {color(ref.get('service','?'), C.BRED)} "
                   f"{color(ref.get('cve') or 'no-cve', C.DIM)}", end="")
        tprint()

    tprint(f"  {color('╚' + '═'*68, C.DIM)}")


# ---------------------------------------------------------------------------
# Auth-redirect warning card
# ---------------------------------------------------------------------------
def print_auth_warning(url: str, redirect_target: str) -> None:
    tprint(f"\n  {color('╔═══ AUTH REQUIRED ═══', C.BYELLOW + C.BOLD)}")
    tprint(f"  {color('║', C.DIM)} {color('endpoint  :', C.DIM)} {color(url, C.BWHITE)}")
    tprint(f"  {color('║', C.DIM)} {color('redirected:', C.DIM)} {color(redirect_target, C.BYELLOW)}")
    tprint(f"  {color('║', C.DIM)} {color('action    :', C.DIM)} "
           f"{color('provide --bearer TOKEN or --cookie NAME=VAL to scan authenticated endpoints', C.DIM)}")
    tprint(f"  {color('╚' + '═'*68, C.DIM)}")


# ---------------------------------------------------------------------------
# Live status board (stderr spinner)
# ---------------------------------------------------------------------------
_BRAILLE = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class StatusBoard:
    """Single-line live status on stderr. Non-intrusive — doesn't pollute stdout."""

    def __init__(self, enabled: bool = True):
        self._enabled  = enabled and not _QUIET
        self._phase    = "init"
        self._detail   = ""
        self._done     = 0
        self._total    = 0
        self._findings = 0
        self._requests = 0
        self._running  = False
        self._thread: Optional[threading.Thread] = None
        self._start    = time.monotonic()
        self._frame    = 0

    def start(self) -> None:
        if not self._enabled:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(1.0)
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()

    def update(
        self,
        phase: str = "",
        detail: str = "",
        done: int = 0,
        total: int = 0,
        requests: int = 0,
        findings: int = 0,
    ) -> None:
        self._phase    = phase or self._phase
        self._detail   = detail
        self._done     = done
        self._total    = total
        if requests:
            self._requests = requests
        if findings:
            self._findings = findings

    def inc_requests(self) -> None:
        self._requests += 1

    def inc_findings(self) -> None:
        self._findings += 1

    def _loop(self) -> None:
        while self._running:
            elapsed  = int(time.monotonic() - self._start)
            m, s     = divmod(elapsed, 60)
            frame    = _BRAILLE[self._frame % len(_BRAILLE)]
            self._frame += 1
            pct      = (f"{int(self._done/self._total*100):3d}%"
                        if self._total else "---")
            status = (
                f"\r\033[2K"
                f"{color(f'{m:02d}:{s:02d}', C.DIM)} "
                f"{color(frame, C.BCYAN)} "
                f"{color('phase:', C.BCYAN)}{color(self._phase[:14], C.BWHITE):<14} "
                f"{color(pct, C.BYELLOW)} "
                f"{color('req:', C.DIM)}{color(str(self._requests), C.BWHITE):<5} "
                f"{color('findings:', C.DIM)}{color(str(self._findings), C.BRED if self._findings else C.DIM):<3} "
                f"{color(self._detail[:30], C.DIM)}"
            )
            sys.stderr.write(status)
            sys.stderr.flush()
            time.sleep(0.12)
