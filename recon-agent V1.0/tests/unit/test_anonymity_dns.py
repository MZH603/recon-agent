"""DNS 反溯源测试：DoH JSON 解析 / 缓存 / doh_strict 语义 / 数字地址直通。"""
import json

import pytest

from security.anonymity import dns_privacy
from security.anonymity.config import AnonymityConfig
from security.anonymity.dns_privacy import DohUnavailableError, doh_resolve, resolve_host


def _fake_doh_response(ips):
    return {"Status": 0, "Answer": [{"name": "example.com.", "type": 1, "data": ip} for ip in ips]}


@pytest.fixture(autouse=True)
def _reset_doh(monkeypatch):
    dns_privacy.clear_doh_cache()
    yield
    dns_privacy.clear_doh_cache()


def test_numeric_host_passthrough():
    """数字地址不经 DoH（HARD：无名称服务交互）。"""
    assert doh_resolve("93.184.216.34") == ["93.184.216.34"]


def test_doh_resolve_parses_json_answers(monkeypatch):
    """DoH JSON API：提取 Answer 中对应 rtype 的 A 记录。"""
    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        status = 200

        def read(self, n=-1):
            return json.dumps(_fake_doh_response(["1.2.3.4", "5.6.7.8"])).encode()

    def fake_build_opener(*args, **kwargs):
        class FakeOpener:
            def open(self, req, timeout=0):
                assert req.full_url.startswith("https://")
                return FakeResp()
        return FakeOpener()

    monkeypatch.setattr(dns_privacy, "build_opener", fake_build_opener)
    monkeypatch.setattr(dns_privacy, "_last_good", "")
    answers = doh_resolve("example.com", "A")
    assert answers == ["1.2.3.4", "5.6.7.8"]


def test_doh_resolve_uses_cache(monkeypatch):
    """TTL 缓存：第二次查询不产生网络请求（防重复 DoH 查询泄露频率特征）。"""
    calls = {"n": 0}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        status = 200

        def read(self, n=-1):
            return json.dumps(_fake_doh_response(["1.2.3.4"])).encode()

    def fake_build_opener(*args, **kwargs):
        class FakeOpener:
            def open(self, req, timeout=0):
                calls["n"] += 1
                return FakeResp()
        return FakeOpener()

    monkeypatch.setattr(dns_privacy, "build_opener", fake_build_opener)
    monkeypatch.setattr(dns_privacy, "_last_good", "")
    assert doh_resolve("cached.example") == ["1.2.3.4"]
    assert doh_resolve("cached.example") == ["1.2.3.4"]
    assert calls["n"] == 1


def test_all_resolvers_fail_raises(monkeypatch):
    """全部解析器失败 → DohUnavailableError。"""
    def fake_build_opener(*args, **kwargs):
        raise OSError("unreachable")

    monkeypatch.setattr(dns_privacy, "build_opener", fake_build_opener)
    monkeypatch.setattr(dns_privacy, "_last_good", "")
    with pytest.raises(DohUnavailableError):
        doh_resolve("dead.example")


def test_resolve_host_strict_blocks_on_doh_failure(monkeypatch):
    """HARD doh_strict=True：DoH 失败拒绝解析（绝不产生本地 DNS 查询）。"""
    def fake_doh_resolve(host, rtype="A", timeout=0):
        raise DohUnavailableError("down")

    monkeypatch.setattr(dns_privacy, "doh_resolve", fake_doh_resolve)
    cfg = AnonymityConfig(doh_enabled=True, doh_strict=True)
    with pytest.raises(DohUnavailableError):
        resolve_host("strict.example", 443, config=cfg)


def test_resolve_host_non_strict_falls_back_to_system(monkeypatch):
    """doh_strict=False：DoH 失败降级系统解析（审计 doh_fallback_system）。"""
    def fake_doh_resolve(host, rtype="A", timeout=0):
        raise DohUnavailableError("down")

    monkeypatch.setattr(dns_privacy, "doh_resolve", fake_doh_resolve)
    cfg = AnonymityConfig(doh_enabled=True, doh_strict=False)
    addrs = resolve_host("localhost", 443, config=cfg)   # hosts 文件可解析，不发起真实 DNS
    assert addrs                                   # 系统 getaddrinfo 正常返回
    assert all(a[0] == socket_family(a) for a in addrs)


def socket_family(entry):
    import socket
    return socket.AF_INET if ":" not in entry[4][0] else socket.AF_INET6


def test_resolve_host_doh_disabled_uses_system(monkeypatch):
    """doh_enabled=False：完全走系统解析（历史行为）。"""
    def boom(*args, **kwargs):
        raise AssertionError("DoH 不应被调用")

    monkeypatch.setattr(dns_privacy, "doh_resolve", boom)
    addrs = resolve_host("localhost", 443, config=AnonymityConfig())
    assert addrs
