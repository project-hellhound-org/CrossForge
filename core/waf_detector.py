"""
HELLHOUND SSRF v5.0 - Phase 3: WAF / Filter Fingerprinting
============================================================
v5 additions:
  [v5-NEW] FortiWeb, Barracuda WAF, Citrix ADC/NetScaler detection
  [v5-NEW] Sucuri, Sophos UTM, Azure Front Door detection
  [v5-NEW] Score-based matching: header_match + body_match + status_match
           weighted sum — reduces false WAF attribution from generic 403s
  [v5-NEW] vendor_confidence score stored on candidate for reporter
"""

from __future__ import annotations
import json
from pathlib import Path

from core.models import Candidate, ProbeResult
from core.http_client import HttpClient

_SIG_PATH = Path(__file__).parent / "payloads" / "waf_signatures.json"
with open(_SIG_PATH) as f:
    _WAF_DATA: dict = json.load(f)

_SIGNATURES: dict     = _WAF_DATA["signatures"]
_MUTATION_CHAINS: dict = _WAF_DATA["mutation_chains"]

# Minimum confidence score to attribute a WAF vendor (0.0 - 1.0)
_MIN_WAF_CONFIDENCE = 0.60

# Canary payloads — designed to provoke WAF responses without being too noisy
_CANARY_PAYLOADS = [
    "http://127.0.0.1/../../../../etc/passwd",   # path traversal canary
    "gopher://127.0.0.1:6379/_INFO",             # protocol-smuggling canary
]


async def fingerprint_waf(client: HttpClient, candidate: Candidate) -> Candidate:
    """
    Sends ≤ len(_CANARY_PAYLOADS) canary probes and fingerprints the WAF vendor.
    Populates candidate.waf_vendor and candidate.mutation_chain.
    Stops early if a high-confidence match is found on the first canary.
    """
    best_vendor:     str | None = None
    best_confidence: float      = 0.0

    for canary in _CANARY_PAYLOADS:
        result = await client.send(
            candidate,
            payload_value=canary,
            payload_category="waf_canary",
        )
        vendor, confidence = _score_signatures(result)
        if vendor and confidence > best_confidence:
            best_vendor     = vendor
            best_confidence = confidence
        if best_confidence >= 0.90:
            break  # high-confidence match — stop early

    candidate.waf_vendor    = best_vendor
    candidate.mutation_chain = get_mutation_chain(best_vendor)
    return candidate


def _score_signatures(result: ProbeResult) -> tuple[str | None, float]:
    """
    Score-based WAF matching: each signal (status, header, body) contributes
    a partial confidence score. Requires a combined score ≥ _MIN_WAF_CONFIDENCE.

    Returns (vendor_name, confidence) or (None, 0.0).
    """
    body_lower    = result.body_snippet.lower()
    headers_lower = {k.lower(): v.lower() for k, v in result.headers.items()}

    best_vendor     = None
    best_confidence = 0.0

    for vendor, sig in _SIGNATURES.items():
        score = 0.0

        # Status code match (necessary condition — no status match → skip)
        if result.status_code not in sig.get("status_codes", []):
            continue
        score += 0.30

        # Header match
        # [Phase 1 rebuild bugfix] Was: an empty-string fragment (meant as
        # "this header is present, value doesn't matter" — e.g. FortiWeb's
        # signature originally had {"x-powered-by": ""}) scored the SAME
        # 0.40 as a genuine vendor-specific substring match. X-Powered-By
        # is a near-universal, non-vendor-specific header (Express sends
        # "X-Powered-By: Express" by default, PHP/ASP.NET have their own
        # defaults) — treating its mere presence as equal evidence to an
        # actual "fortigate" string match meant status_code alone (0.30)
        # plus ANY app that happens to send ANY X-Powered-By header (0.40)
        # cleared the 0.60 threshold with zero vendor-specific evidence.
        # Observed in the field: 44/48 candidates against a plain Express
        # app (OWASP Juice Shop, no WAF in front of it at all) misattributed
        # to FortiWeb, purely from 400/403 statuses + a generic header.
        # Fix: presence-only (empty-fragment) matches are a weak signal
        # (0.15), genuine substring matches stay a strong signal (0.40) —
        # and the strongest available match wins, not the first-in-dict-
        # order one, so a weak match earlier in the signature JSON can't
        # shadow a strong match later in it.
        header_score = 0.0
        for h_name, h_fragment in sig.get("header_contains", {}).items():
            h_name_lower = h_name.lower()
            actual       = headers_lower.get(h_name_lower, "")
            if h_fragment == "":
                if h_name_lower in headers_lower:
                    header_score = max(header_score, 0.15)
            elif h_fragment.lower() in actual:
                header_score = max(header_score, 0.40)
        score += header_score

        # Body match
        body_frags = sig.get("body_contains", [])
        if body_frags:
            matched_frags = sum(
                1 for frag in body_frags if frag.lower() in body_lower
            )
            if matched_frags:
                score += 0.30 * (matched_frags / len(body_frags))

        if score >= _MIN_WAF_CONFIDENCE and score > best_confidence:
            best_confidence = score
            best_vendor     = vendor

    return best_vendor, best_confidence


def is_blocked(result: ProbeResult, waf_vendor: str | None) -> bool:
    """Returns True if this specific response matches the fingerprinted WAF's block signature."""
    if not waf_vendor:
        return False
    sig = _SIGNATURES.get(waf_vendor, {})
    if result.status_code not in sig.get("status_codes", []):
        return False
    body_lower = result.body_snippet.lower()
    return any(frag.lower() in body_lower for frag in sig.get("body_contains", []))


def get_mutation_chain(waf_vendor: str | None) -> list[str]:
    """Single source of truth: vendor → mutation chain."""
    return _MUTATION_CHAINS.get(waf_vendor or "none", _MUTATION_CHAINS["none"])
