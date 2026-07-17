"""
CrossForge SSRF Agent — Recon Quality Gate (Phase 1 addition)
================================================================
WHY THIS MODULE EXISTS
------------------------
core/crawler.py records an endpoint as soon as it gets *any* HTTP response
— it never asks whether that response is a real page. Two very common
failure modes exploit that gap and inflate Phase 0's candidate queue with
noise before triage even starts:

  1. SOFT-404: the app returns HTTP 200 for every unknown path (common on
     SPA shells with client-side routing, or CMSs with a catch-all
     controller). Every crawled link, whether real or guessed, "succeeds"
     and gets recorded identically.
  2. BOT-BLOCK / CHALLENGE PAGE: a WAF or bot-mitigation vendor (Cloudflare,
     Akamai, PerimeterX, DataDome, Imperva, generic anti-automation
     middleware) intercepts the crawler's requests and serves a challenge
     or "access denied" page instead of the real app. Every subsequent
     page looks byte-identical, and the crawler happily records dozens of
     "endpoints" that are really the same interstitial page.

Both cases share a signature: once you've seen the junk page once, every
later page that looks the same is junk too. This module establishes that
signature once per crawl (a small canary probe against paths that cannot
legitimately exist) and gives the crawler a single classification call to
run against every subsequent response.

WHAT THIS MODULE IS DELIBERATELY NOT
----------------------------------------
This is NOT a replacement for core/waf_detector.py's Phase 3 vendor
fingerprinting. That module does deep, per-candidate signature matching
(headers, body markers, status codes) against 11 named WAF vendors to
choose an evasion mutation chain — a scanning-time decision. This module
runs once, at crawl time, purely to stop the crawler's OWN discovery pass
from mistaking a challenge/error page for real application content. The
bot-block phrase list here is intentionally small and generic; it exists
to catch the page, not to identify the vendor. If a candidate specifically
needs vendor-aware evasion, that's Phase 3's job, not this module's.

DESIGN
--------
  - `establish_baseline()` fetches a small number of GET-random,
    almost-certainly-nonexistent paths under the target's own scope
    (never a real observed path) and fingerprints the response(s).
  - `classify_response()` compares a live response against that baseline
    plus a running set of "already seen" body signatures. Three outcomes:
      REAL            — record it, parse it, keep crawling from it.
      SOFT_404        — matches the canary signature; still worth noting
                         once (the app doesn't do real 404s) but don't
                         treat its links/forms/JS as real discovery.
      DUPLICATE_SHELL — not the canary signature specifically, but
                         byte-identical (via content hash) to ≥3 prior
                         "REAL" pages already seen this crawl — the
                         signature of a bot-block interstitial or a
                         SPA shell being served for every route.
  - Both non-REAL outcomes still count toward the page budget (a filtered
    request still cost a request) but never get parsed for links/forms/JS
    and never become a Phase-0 candidate.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

import httpx

# ---------------------------------------------------------------------------
# Bot-block / challenge-page phrase list — intentionally small and generic.
# See module docstring: NOT a vendor fingerprint list, that's waf_detector.py.
# ---------------------------------------------------------------------------
_BOT_BLOCK_MARKERS = re.compile(
    r"(checking your browser|attention required|access denied|"
    r"request blocked|automated request|are you a human|"
    r"please verify you are human|unusual traffic|"
    r"ray id|cf-challenge|captcha|bot detection|"
    r"blocked by (?:the )?firewall|security service to protect)",
    re.IGNORECASE,
)

# Paths that legitimately cannot exist on a normal application — used only
# to fingerprint what "not found" looks like on THIS target, never fetched
# as if they might be real. A random UUID guarantees no collision with a
# genuine route.
_CANARY_PATH_TEMPLATES = [
    "/__crossforge-canary-{token}__",
    "/__crossforge-canary-{token}__.html",
]

_DUPLICATE_SHELL_THRESHOLD = 3   # ≥N identical bodies among REAL pages → shell/block


class QualityVerdict(str, Enum):
    REAL            = "real"
    SOFT_404        = "soft_404"
    BOT_BLOCKED     = "bot_blocked"
    DUPLICATE_SHELL = "duplicate_shell"


@dataclass
class QualityBaseline:
    established:       bool = False
    canary_status:      int | None = None
    canary_hash:        str | None = None
    canary_length:      int = 0
    # content-hash -> count of REAL pages seen with that exact body, so
    # far this crawl. Populated incrementally by classify_response().
    _seen_body_hashes:  dict[str, int] = field(default_factory=dict)
    stats: dict = field(default_factory=lambda: {
        "soft_404_filtered": 0, "bot_blocked_filtered": 0,
        "duplicate_shell_filtered": 0,
    })


def _hash_body(body: str) -> str:
    # Normalise obvious per-request noise (CSRF tokens, timestamps, nonces)
    # before hashing so two structurally-identical pages hash the same even
    # if they embed a fresh token each time — otherwise every soft-404 page
    # would hash differently and the duplicate-shell check would never fire.
    normalised = re.sub(r"[0-9a-fA-F]{16,}", "", body)          # long hex tokens
    normalised = re.sub(r"\b\d{10,}\b", "", normalised)          # timestamps/ids
    normalised = re.sub(r"\s+", " ", normalised).strip()
    return hashlib.sha256(normalised.encode("utf-8", errors="ignore")).hexdigest()


async def establish_baseline(
    client: httpx.AsyncClient, base_url: str, timeout: float = 8.0,
) -> QualityBaseline:
    """
    One-time canary probe, run at the start of a crawl. Never raises —
    a failed canary probe just leaves the baseline "not established" and
    classify_response() falls back to duplicate-shell detection only.
    """
    baseline = QualityBaseline()
    token = uuid.uuid4().hex[:16]
    for template in _CANARY_PATH_TEMPLATES:
        path = template.format(token=token)
        try:
            url = base_url.rstrip("/") + path
            resp = await client.get(url, timeout=timeout)
            baseline.canary_status = resp.status_code
            baseline.canary_hash   = _hash_body(resp.text)
            baseline.canary_length = len(resp.content)
            baseline.established   = True
            break
        except Exception:
            continue
    return baseline


def classify_response(
    baseline: QualityBaseline, status: int, body: str,
) -> QualityVerdict:
    """
    Called once per fetched page, BEFORE the crawler parses it for
    links/forms/JS. Mutates baseline's internal seen-hash counter for REAL
    pages so later duplicate-shell detection has something to compare
    against — call this exactly once per fetch, in fetch order.
    """
    if _BOT_BLOCK_MARKERS.search(body[:4000]):
        baseline.stats["bot_blocked_filtered"] += 1
        return QualityVerdict.BOT_BLOCKED

    body_hash = _hash_body(body)

    if baseline.established and status == baseline.canary_status and body_hash == baseline.canary_hash:
        baseline.stats["soft_404_filtered"] += 1
        return QualityVerdict.SOFT_404

    seen_count = baseline._seen_body_hashes.get(body_hash, 0)
    if seen_count >= _DUPLICATE_SHELL_THRESHOLD:
        baseline.stats["duplicate_shell_filtered"] += 1
        return QualityVerdict.DUPLICATE_SHELL

    baseline._seen_body_hashes[body_hash] = seen_count + 1
    return QualityVerdict.REAL
