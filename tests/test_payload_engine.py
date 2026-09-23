"""
tests/test_payload_engine.py — Unit tests for v2.0 payload engine additions
"""

import pytest
from core.payload_engine import (
    build_parser_confusion_payloads,
    build_dns_rebinding_payloads,
    build_ssrf_payload,
    apply_ip_mutation,
    ip_to_decimal,
    ip_to_hex,
    ip_to_octal,
    ip_to_dotted_hex,
    ip_to_ipv6_mapped,
)


# ---------------------------------------------------------------------------
# Test existing IP mutations
# ---------------------------------------------------------------------------

def test_ip_to_decimal():
    assert ip_to_decimal("127.0.0.1") == "2130706433"


def test_ip_to_hex():
    assert ip_to_hex("127.0.0.1") == "0x7f000001"


def test_ip_to_octal():
    result = ip_to_octal("127.0.0.1")
    assert "0177" in result


def test_ip_to_ipv6_mapped():
    assert ip_to_ipv6_mapped("127.0.0.1") == "[::ffff:127.0.0.1]"


def test_apply_ip_mutation():
    url = "http://127.0.0.1:80/"
    result = apply_ip_mutation(url, "ip_decimal")
    assert "2130706433" in result


def test_build_ssrf_payload_basic():
    url = build_ssrf_payload("10.0.0.1", 8080, "http", "/admin")
    assert url == "http://10.0.0.1:8080/admin"


def test_build_ssrf_payload_with_mutation():
    url = build_ssrf_payload("127.0.0.1", 80, mutation="ip_hex")
    assert "0x7f000001" in url


# ---------------------------------------------------------------------------
# [v2] Test parser confusion payloads
# ---------------------------------------------------------------------------

def test_parser_confusion_payloads_not_empty():
    payloads = build_parser_confusion_payloads()
    assert len(payloads) > 10  # Should have many techniques


def test_parser_confusion_payloads_structure():
    payloads = build_parser_confusion_payloads("10.0.0.1", "evil.com")
    for p in payloads:
        assert "payload" in p
        assert "technique" in p
        assert "category" in p
        assert isinstance(p["payload"], str)


def test_parser_confusion_at_credential():
    payloads = build_parser_confusion_payloads("10.0.0.1", "evil.com")
    at_creds = [p for p in payloads if p["technique"] == "at_credential_confusion"]
    assert len(at_creds) == 1
    assert "evil.com@10.0.0.1" in at_creds[0]["payload"]


def test_parser_confusion_short_forms():
    payloads = build_parser_confusion_payloads()
    techniques = {p["technique"] for p in payloads}
    assert "short_form_127_1" in techniques
    assert "hex_loopback" in techniques
    assert "decimal_loopback" in techniques


def test_parser_confusion_dns_bypass():
    payloads = build_parser_confusion_payloads()
    dns_bypasses = [p for p in payloads if p["category"] == "dns_bypass"]
    assert len(dns_bypasses) >= 3
    domains = [p["payload"] for p in dns_bypasses]
    assert any("localtest.me" in d for d in domains)
    assert any("nip.io" in d for d in domains)


# ---------------------------------------------------------------------------
# [v2] Test DNS rebinding payloads
# ---------------------------------------------------------------------------

def test_dns_rebinding_payloads():
    payloads = build_dns_rebinding_payloads(
        "192.168.1.1", ["127.0.0.1", "10.0.0.1"]
    )
    assert len(payloads) == 2
    for p in payloads:
        assert p["technique"] == "dns_rebinding_toctou"
        assert p["category"] == "dns_rebinding"
        assert "rebind-" in p["payload"]
        assert "meta" in p
        assert "domain" in p["meta"]


def test_dns_rebinding_hex_format():
    payloads = build_dns_rebinding_payloads("192.168.0.1", ["127.0.0.1"])
    assert len(payloads) == 1
    domain = payloads[0]["meta"]["domain"]
    # 192.168.0.1 = c0a80001, 127.0.0.1 = 7f000001
    assert "c0a80001" in domain
    assert "7f000001" in domain


def test_dns_rebinding_invalid_ip():
    payloads = build_dns_rebinding_payloads("not-an-ip", ["127.0.0.1"])
    assert len(payloads) == 0


def test_dns_rebinding_custom_base_domain():
    payloads = build_dns_rebinding_payloads(
        "192.168.0.1", ["127.0.0.1"], base_domain="rebind.example.com"
    )
    assert "rebind.example.com" in payloads[0]["meta"]["domain"]
