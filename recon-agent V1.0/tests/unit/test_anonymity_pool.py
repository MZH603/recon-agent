"""代理 IP 池测试：轮换策略 / 冷却剔除 / sticky 稳定性 / 池耗尽 / 审计脱敏。"""
from security.anonymity.config import ProxyEndpoint
from security.anonymity.pool import ProxyPool, _mask


def _pool(rotation="sticky", cooldown=600, n=3):
    endpoints = [ProxyEndpoint(url=f"socks5://10.0.0.{i}:1080", tag=f"p{i}") for i in range(1, n + 1)]
    return ProxyPool(endpoints, rotation=rotation, fail_cooldown_seconds=cooldown)


def test_sticky_rotation_same_target_stable():
    """HARD 语义：同一目标键在无故障时固定同一出口（防 IP 抖动关联指纹）。"""
    pool = _pool()
    first = pool.acquire("target-a")
    for _ in range(5):
        assert pool.acquire("target-a").url == first.url


def test_sticky_rotation_varies_across_targets():
    """不同目标键之间应分布到不同出口（跨目标轮换）。"""
    pool = _pool()
    chosen = {pool.acquire(f"target-{i}").url for i in range(6)}
    assert len(chosen) >= 2


def test_round_robin_cycles():
    """round_robin 严格顺序轮转，不重复。"""
    pool = _pool(rotation="round_robin")
    order = [pool.acquire("t").url for _ in range(3)]
    assert len(set(order)) == 3


def test_failure_cooldown_removes_endpoint():
    """失败出口进入冷却期，acquire 不再返回（HARD：防半死出口拖慢流量）。"""
    pool = _pool(rotation="round_robin")
    broken = pool.acquire("t")
    pool.report_failure(broken)
    for _ in range(6):
        assert pool.acquire("t").url != broken.url


def test_success_clears_cooldown():
    """成功报告重置失败计数与冷却状态。"""
    pool = _pool(rotation="round_robin")
    ep = pool.acquire("t")
    pool.report_failure(ep)
    pool.report_success(ep, latency_ms=120.0)
    state_ok = any(s.endpoint.url == ep.url for s in pool._states)
    assert state_ok
    assert pool.healthy_count() == 3


def test_pool_exhausted_returns_none_and_audits():
    """全部出口冷却时 acquire 返回 None（调用方须 fail closed），并产生 pool_exhausted 审计。"""
    import json
    from utils.logger import audit_path
    pool = _pool(cooldown=3600)
    for ep in [ProxyEndpoint(url=s.endpoint.url) for s in pool._states]:
        pool.report_failure(ep)
    assert pool.healthy_count() == 0
    assert pool.acquire("t") is None
    entries = [json.loads(line) for line in audit_path().read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "pool_exhausted" for e in entries)


def test_audit_masks_proxy_credentials():
    """审计中的代理 URL 必须脱敏（HARD：不落凭据明文）。"""
    masked = _mask("socks5://user:secret@10.0.0.1:1080")
    assert "user" not in masked and "secret" not in masked
    assert masked.startswith("socks5://10.0.0.1:1080")


def test_single_endpoint_pool_never_none_when_healthy():
    """single 模式（单出口池）：健康时永远可得。"""
    pool = ProxyPool([ProxyEndpoint(url="socks5://10.0.0.9:1080")])
    assert pool.acquire("any").url == "socks5://10.0.0.9:1080"
    assert pool.acquire("other").url == "socks5://10.0.0.9:1080"
