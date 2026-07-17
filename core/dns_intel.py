"""
CrossForge SSRF Agent — DNS Intelligence (Phase 1 addition)
================================================================
WHY THIS MODULE EXISTS
------------------------
Two independent uses:

  1. RECON BREADTH: MX/TXT/NS records routinely reveal in-scope
     infrastructure a pure web-crawl never touches (SPF/DMARC TXT records
     naming a mail-relay host, NS records naming an internal-sounding
     nameserver, CNAME chains through a CDN or load balancer). Informational
     only — never auto-added to crawl scope (see core/crawler.py's
     [Safety-2] scope-guard note); surfaced in the crawl summary for the
     operator to decide whether to add via --crawl-scope.

  2. PREREQUISITE FOR A REAL DNS-REBINDING DETECTOR: the evaluation report
     for this codebase flagged core/chaining.py's `detect_dns_rebinding()`
     as structurally broken — it compares the resolved IP of the TARGET
     APPLICATION's own hostname (from core/http_client.py's per-request
     `_resolve_host()`), never the hostname embedded in an SSRF payload,
     which is what a real TOCTOU rebind attack depends on. Fixing that
     requires a resolver CrossForge controls independent of httpx's
     connection-time resolution — this module is that independent
     resolver. It does nothing about the rebind detector itself yet; it
     just makes the DNS layer a first-class, directly-callable capability
     instead of something buried inside the HTTP client's connection
     handling.

OPTIONAL DEPENDENCY, GRACEFUL DEGRADE
------------------------------------------
Full record-type enumeration (CNAME/MX/TXT/NS) needs a real DNS library —
the stdlib `socket` module only exposes A/AAAA (via `getaddrinfo`), it has
no concept of an MX or TXT record. Same pattern already used for the
headless-render pass in core/crawler.py: try the real capability, and if
the optional dependency (`dnspython`) isn't installed, fall back to
what stdlib alone can do rather than failing the whole module.

    pip install 'crossforge[dns]'   # installs dnspython

Every lookup runs in a thread (`asyncio.to_thread`) because both
`socket.getaddrinfo` and `dnspython`'s resolver are blocking calls — this
keeps the crawler's event loop free the same way every other I/O in this
codebase is async.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

try:
    import dns.resolver  # optional — dnspython
    _HAVE_DNSPYTHON = True
except ImportError:
    _HAVE_DNSPYTHON = False


@dataclass
class DNSRecordSet:
    host:        str
    a:           list[str] = field(default_factory=list)
    aaaa:        list[str] = field(default_factory=list)
    cname:       list[str] = field(default_factory=list)
    mx:          list[str] = field(default_factory=list)
    txt:         list[str] = field(default_factory=list)
    ns:          list[str] = field(default_factory=list)
    error:       str | None = None
    full_enumeration: bool = False   # True only if dnspython was available


def _resolve_via_getaddrinfo(host: str) -> tuple[list[str], list[str]]:
    a, aaaa = [], []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in a:
                a.append(ip)
            elif family == socket.AF_INET6 and ip not in aaaa:
                aaaa.append(ip)
    except socket.gaierror:
        pass
    return a, aaaa


def _resolve_via_dnspython(host: str, timeout: float) -> DNSRecordSet:
    rs = DNSRecordSet(host=host, full_enumeration=True)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    def _query(rtype: str) -> list[str]:
        try:
            answer = resolver.resolve(host, rtype)
            return [str(r).rstrip(".") for r in answer]
        except Exception:
            return []

    rs.a     = _query("A")
    rs.aaaa  = _query("AAAA")
    rs.cname = _query("CNAME")
    rs.mx    = _query("MX")
    rs.txt   = _query("TXT")
    rs.ns    = _query("NS")
    return rs


def _resolve_sync(host: str, timeout: float) -> DNSRecordSet:
    if _HAVE_DNSPYTHON:
        try:
            return _resolve_via_dnspython(host, timeout)
        except Exception as exc:
            # Fall through to the getaddrinfo-only path rather than losing
            # the lookup entirely because the fuller path hit an edge case.
            rs = DNSRecordSet(host=host, error=str(exc))
    else:
        rs = DNSRecordSet(host=host)
    rs.a, rs.aaaa = _resolve_via_getaddrinfo(host)
    return rs


async def resolve_host(host: str, timeout: float = 5.0) -> DNSRecordSet:
    return await asyncio.to_thread(_resolve_sync, host, timeout)


async def resolve_hosts(
    hosts: list[str], timeout: float = 5.0, concurrency: int = 5,
) -> dict[str, DNSRecordSet]:
    """Batch resolve, bounded concurrency — used for base host + any
    subdomains subdomain_enum.py turned up, so a crawl against a target
    with dozens of discovered subdomains doesn't serialise DNS lookups."""
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(h: str) -> tuple[str, DNSRecordSet]:
        async with sem:
            return h, await resolve_host(h, timeout)

    results = await asyncio.gather(*[_bounded(h) for h in hosts], return_exceptions=True)
    out: dict[str, DNSRecordSet] = {}
    for r in results:
        if isinstance(r, Exception):
            continue
        host, rs = r
        out[host] = rs
    return out
