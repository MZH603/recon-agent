"""多目标类型兼容矩阵（域名/IP/IPv6/host:port/URL/边界形态）。"""
import pytest

from security.stealth import allowed_target, is_in_scope, normalize_host
from tools.builtin.fingerprint import split_target


# ---- split_target：主机/端口/scheme 解析 ----
def test_split_target_domain():
    assert split_target("example.com") == ("example.com", None, "")


def test_split_target_host_port():
    assert split_target("127.0.0.1:8080") == ("127.0.0.1", 8080, "")
    assert split_target("example.com:8443") == ("example.com", 8443, "")


def test_split_target_url_forms():
    assert split_target("https://example.com") == ("example.com", None, "https")
    assert split_target("http://example.com:8080/x") == ("example.com", 8080, "http")
    assert split_target("http://127.0.0.1:9000/a") == ("127.0.0.1", 9000, "http")


def test_split_target_ipv6():
    # IPv6 裸地址（多冒号）不得被误拆为 host:port
    assert split_target("::1") == ("::1", None, "")
    assert split_target("2001:db8::1") == ("2001:db8::1", None, "")
    # 括号形式支持端口
    assert split_target("[::1]:8080") == ("::1", 8080, "")


def test_split_target_trailing_dot_and_uppercase():
    host, _, _ = split_target("EXAMPLE.COM.")
    assert host.lower() == "example.com."


# ---- normalize_host： scheme/路径/端口剥离 + IPv6 保真 ----
def test_normalize_host_strips_scheme_path_port():
    assert normalize_host("https://example.com/a?b=1") == "example.com"
    assert normalize_host("http://example.com:8080/") == "example.com"


def test_normalize_host_ipv6_preserved():
    assert normalize_host("2001:db8::1") == "2001:db8::1"
    assert normalize_host("http://[::1]:8080/") in ("::1", "[::1]")


# ---- allowed_target：各形态目标的合规判定 ----
def test_allowed_target_accepts_public_forms():
    s = get_settings()
    for t in ("example.com", "93.184.216.34", "scanme.nmap.org", "EXAMPLE.COM"):
        ok, _ = allowed_target(t, s)
        assert ok, t


def test_allowed_target_rejects_private_and_protected():
    s = get_settings()
    for t in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "localhost",
              "169.254.169.254", "site.gov", "www.gov.cn", "x.mil"):
        ok, _ = allowed_target(t, s)
        assert not ok, t


def test_allowed_target_lab_unlocks_only_private():
    from utils.config import Settings

    s = Settings()
    s.LAB_MODE = True
    assert allowed_target("127.0.0.1", s)[0]
    assert allowed_target("::1", s)[0]
    assert not allowed_target("169.254.169.254", s)[0]   # 元数据地址仍拒绝
    assert not allowed_target("a.gov.cn", s)[0]          # 政府域名仍拒绝


# ---- is_in_scope：子域/IP/CIDR 形态 ----
def test_in_scope_domain_forms():
    assert is_in_scope("example.com", "example.com")
    assert is_in_scope("oa.example.com", "example.com")
    assert not is_in_scope("evil.com", "example.com")


def test_in_scope_ip_exact_only():
    assert is_in_scope("93.184.216.34", "93.184.216.34")
    assert not is_in_scope("93.184.216.1", "93.184.216.34")  # 同 C 段 ≠ 范围内


from utils.config import get_settings  # noqa: E402
