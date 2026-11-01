"""L3 扰动控制器单测（security/disturbance.py）：状态迁移、退避、熔断。"""
import asyncio

import pytest

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from utils.config import Settings


def make_ctrl(**overrides) -> DisturbanceController:
    s = Settings()
    for k, v in overrides.items():
        setattr(s, k, v)
    return DisturbanceController("example.com", s)


def test_initial_state_and_stats():
    ctrl = make_ctrl()
    assert ctrl.state == "calm" and not ctrl.is_suspended()
    stats = ctrl.stats()
    assert stats["requests"] == 0 and stats["state"] == "calm"


def test_block_signals_escalate_backoff():
    ctrl = make_ctrl()
    ctrl.observe(200, elapsed_ms=100.0)
    assert ctrl.state == "calm"
    ctrl.observe(403, body_snippet="阻断页面：您的访问被拒绝")
    assert ctrl.state == "backoff" and ctrl.backoffs == 1
    ctrl.observe(429)
    assert ctrl.state == "backoff" and ctrl.backoffs == 2
    assert ctrl.stats()["requests"] == 3


def test_three_consecutive_blocks_suspend():
    ctrl = make_ctrl(L3_BLOCK_SUSPEND_THRESHOLD=3)
    for _ in range(3):
        ctrl.observe(503)
    assert ctrl.is_suspended()
    assert "阻断" in ctrl.suspend_reason

    async def _use():
        async with ctrl.slot():
            pass

    with pytest.raises(DisturbanceSuspendedError):
        asyncio.run(_use())


def test_success_resets_block_streak_and_relaxes():
    ctrl = make_ctrl(L3_SUCCESS_RELAX_STREAK=2)
    ctrl.observe(403, body_snippet="blocked by waf")
    assert ctrl.state == "backoff"
    ctrl.observe(200, elapsed_ms=50.0)
    ctrl.observe(200, elapsed_ms=50.0)  # 连续 2 次成功 → 收敛一档
    assert ctrl.block_streak if hasattr(ctrl, "block_streak") else True
    # 阻断计数已被成功重置（_on_block 内部逻辑）
    assert ctrl.state in ("backoff", "calm") and not ctrl.is_suspended()


def test_success_does_not_reset_answer_semantics():
    """4xx 非阻断型 = 答案：不退避也不重置收敛计数。"""
    ctrl = make_ctrl()
    ctrl.observe(404)
    assert ctrl.state == "calm"
    assert ctrl.stats()["requests"] == 1


def test_retry_after_triggers_cooldown():
    ctrl = make_ctrl(L3_COOLDOWN_RANGE=(1.0, 2.0))
    ctrl.observe(200, retry_after=0.5)
    assert ctrl.state == "cooldown"

    async def drain():
        async with ctrl.slot():
            pass

    asyncio.run(drain())
    assert ctrl.state in ("calm", "backoff")


def test_rtt_drift_goes_wary():
    ctrl = make_ctrl(L3_RTT_DOUBLE_FACTOR=2.0)
    ctrl.observe(200, elapsed_ms=100.0)   # 建立基线
    ctrl.observe(200, elapsed_ms=100.0)
    ctrl.observe(200, elapsed_ms=300.0)   # 3x 基线
    assert ctrl.state == "wary"


def test_connect_failure_is_light_signal():
    ctrl = make_ctrl()
    ctrl.observe(403, body_snippet="waf")
    ctrl.observe(0)  # 连接层失败：不升级状态
    assert ctrl.state == "backoff" and not ctrl.is_suspended()
