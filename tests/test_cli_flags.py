"""
tests/test_cli_flags.py — Unit tests for v2.0 CLI flag additions
"""

import pytest
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import build_parser, patch_config


# ---------------------------------------------------------------------------
# Test new CLI flags parse correctly
# ---------------------------------------------------------------------------

def test_oob_wait_flag():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--oob-wait", "300"])
    assert args.oob_wait == 300.0


def test_oob_wait_default_none():
    p = build_parser()
    args = p.parse_args(["http://target.com"])
    assert args.oob_wait is None


def test_dns_rebind_flag():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--dns-rebind"])
    assert args.dns_rebind is True


def test_dns_rebind_default_false():
    p = build_parser()
    args = p.parse_args(["http://target.com"])
    assert args.dns_rebind is False


def test_mode_choices():
    p = build_parser()
    for mode in ["detect", "default", "exploit_chain", "no"]:
        args = p.parse_args(["http://target.com", "--mode", mode])
        assert args.mode == mode


def test_mode_detect_exploit_removed():
    """v1's 'detect_exploit' is no longer a valid choice."""
    p = build_parser()
    with pytest.raises(SystemExit):
        p.parse_args(["http://target.com", "--mode", "detect_exploit"])


# ---------------------------------------------------------------------------
# Test patch_config wiring
# ---------------------------------------------------------------------------

def test_patch_config_oob_wait():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--oob-wait", "120"])
    cfg = {}
    patch_config(cfg, args)
    assert cfg["oob"]["oob_wait"] == 120.0


def test_patch_config_dns_rebind():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--dns-rebind"])
    cfg = {}
    patch_config(cfg, args)
    assert cfg["chaining"]["dns_rebind_server"] is True


def test_patch_config_mode_exploit_chain():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--mode", "exploit_chain"])
    cfg = {}
    patch_config(cfg, args)
    assert cfg["exploitation"]["auto_mode"] == "exploit_chain"
    assert cfg["scan_mode"] == "exploit_chain"


def test_patch_config_mode_default():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--mode", "default"])
    cfg = {}
    patch_config(cfg, args)
    assert cfg["exploitation"]["auto_mode"] == "default"


def test_patch_config_mode_no():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--mode", "no"])
    cfg = {}
    patch_config(cfg, args)
    assert cfg["exploitation"]["auto_mode"] == "no"


def test_patch_config_mode_detect():
    """'detect' mode doesn't set exploitation auto_mode."""
    p = build_parser()
    args = p.parse_args(["http://target.com", "--mode", "detect"])
    cfg = {}
    patch_config(cfg, args)
    assert "exploitation" not in cfg  # detect isn't in the auto_mode list
    assert cfg["scan_mode"] == "detect"


def test_patch_config_proxy():
    p = build_parser()
    args = p.parse_args(["http://target.com", "--proxy", "http://127.0.0.1:8080"])
    cfg = {}
    patch_config(cfg, args)
    assert cfg["http"]["proxy"] == "http://127.0.0.1:8080"


def test_version_string():
    from main import VERSION
    assert VERSION == "2.0.0"
