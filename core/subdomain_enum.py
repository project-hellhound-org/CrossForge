"""
CrossForge SSRF Agent — Subdomain Enumeration via Certificate Transparency
================================================================================
WHY THIS MODULE EXISTS
------------------------
core/crawler.py's scope guard ([Safety-2] in that module) is same-origin by
default — it will never itself go find sibling hosts. That's the right
default for a crawler (an attacker-controlled `--crawl-scope` expansion
should be an explicit operator decision, not something the crawler infers
mid-run), but it also means a real SSRF sink living on
`internal-api.target.com` or `webhooks.target.com` — genuinely common
naming for exactly the kind of service that has an SSRF-relevant surface —
is invisible to a crawl scoped to `www.target.com` alone.

This is PASSIVE reconnaissance: it queries public Certificate Transparency
log aggregators (crt.sh) for certificates that were ever issued naming a
subdomain of the target — it never sends a single packet to the target
itself. Results are reported for the operator to review and add via
`--crawl-scope` (or the equivalent config list) if they're in-scope for
the engagement; this module does not, on its own, expand what the crawler
is allowed to fetch. See core/crawler.py's `_run_subdomain_enum()` call
site for how the results are surfaced without silently widening scope.

RELIABILITY NOTE
-------------------
crt.sh is a free, best-effort, third-party public service with no uptime
SLA — it is routinely slow and occasionally returns malformed/partial
responses under load. Every failure mode here degrades to an empty result
with a logged reason, never an exception that would abort the crawl.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote

import httpx

_CRTSH_URL = "https://crt.sh/?q={query}&output=json"
_VALID_HOST_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-.]{0,251}[a-zA-Z0-9])?$")


def _clean_name(raw: str) -> str | None:
    name = raw.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    if not name or " " in name or not _VALID_HOST_RE.match(name):
        return None
    return name


async def enumerate_subdomains(
    domain: str,
    client: httpx.AsyncClient | None = None,
    timeout: float = 12.0,
    limit: int = 50,
) -> dict:
    """
    Returns {"subdomains": [...], "source": "crt.sh", "queried": bool,
    "skip_reason": str|None}. Never raises.
    """
    result = {"subdomains": [], "source": "crt.sh", "queried": False, "skip_reason": None}

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True)

    try:
        url = _CRTSH_URL.format(query=quote(f"%.{domain}"))
        try:
            resp = await client.get(url, headers={"Accept": "application/json"})
        except Exception as exc:
            result["skip_reason"] = f"crt.sh request failed: {exc}"
            return result

        result["queried"] = True
        if resp.status_code != 200:
            result["skip_reason"] = f"crt.sh returned HTTP {resp.status_code}"
            return result

        try:
            rows = json.loads(resp.text)
        except json.JSONDecodeError:
            # crt.sh occasionally returns HTML (rate-limit/maintenance page)
            # instead of the documented JSON — degrade cleanly rather than
            # raise out of a best-effort recon step.
            result["skip_reason"] = "crt.sh response was not valid JSON (likely rate-limited)"
            return result

        found: set[str] = set()
        for row in rows:
            name_value = row.get("name_value", "")
            # crt.sh packs multiple SANs from one certificate into a single
            # newline-separated name_value field.
            for candidate in name_value.split("\n"):
                cleaned = _clean_name(candidate)
                if cleaned and cleaned.endswith(domain.lower()) and cleaned != domain.lower():
                    found.add(cleaned)

        result["subdomains"] = sorted(found)[:limit]
        return result
    finally:
        if own_client:
            await client.aclose()
