"""隐蔽性强制测试（参数修正 / 合规名单 / 范围锁定）。"""
from utils.config import get_settings
from security.stealth import (
    allowed_target,
    enforce_stealth,
    is_in_scope,
    sanitize_concurrency,
)


def test_forbidden_nmap_args_removed_and_safe_inserted():
    out, log = enforce_stealth("nmap", ["nmap", "-sS", "-sV", "-T4", "-p", "80,443", "example.com"])
    assert "-sS" not in out and "-sV" not in out and "-T4" not in out
    assert "-sT" in out and "--max-rate" in out
    assert log, "修正必须有日志"


def test_concurrency_capped_at_hard_limit():
    assert sanitize_concurrency(100) == 2
    assert sanitize_concurrency(0) == 1


def test_protected_tld_rejected():
    ok, reason = allowed_target("sub.example.gov", get_settings())
    assert not ok and "TLD" in reason


def test_rfc1918_and_localhost_rejected():
    ok1, _ = allowed_target("10.1.2.3", get_settings())
    ok2, _ = allowed_target("192.168.1.1", get_settings())
    ok3, _ = allowed_target("localhost", get_settings())
    assert not ok1 and not ok2 and not ok3


def test_lab_mode_unlocks_private_targets_only():
    """--lab 仅解锁自有内网/环回实验目标；政府军事与元数据地址仍绝对拒绝（HARD）。"""
    from utils.config import Settings

    s = Settings()
    s.LAB_MODE = True
    assert allowed_target("192.168.1.50", s)[0]
    assert allowed_target("10.0.0.8", s)[0]
    assert allowed_target("localhost", s)[0]
    assert allowed_target("127.0.0.1", s)[0]
    # 绝对红线不受 lab 模式影响
    assert not allowed_target("defense.mil", s)[0]
    assert not allowed_target("www.army.mil", s)[0]
    assert not allowed_target("169.254.169.254", s)[0]
    assert not allowed_target("site.gov", s)[0]


def test_scope_lock():
    assert is_in_scope("example.com", "example.com")
    assert is_in_scope("a.b.example.com", "example.com")
    assert not is_in_scope("notexample.com", "example.com")
    assert not is_in_scope("partner-company.cn", "example.com")  # 关联资产 ≠ 范围内
