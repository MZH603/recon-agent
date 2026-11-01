"""L3 自适应扰动控制器（HARD：绝对底线 = 不影响目标正常活动；熔断即停，绝不硬闯）。

三层决策框架：
- 绝对底线（不可越）：零写入、零凭据爆破、零 flood；目标出现不适信号立即退避；
  连续阻断 → 熔断该主机（sampling_suspended），损失写进报告，不硬闯。
- 执行目标（不可降）：全面度靠"更大采样面 + 向目标学习耐受度"保证，不靠硬闯。
- 调节手段：从响应读取耐受信号（429/503/Retry-After/阻断页/连续 RST/RTT 漂移），
  动态调节延迟 ∈ [L3_DELAY_FLOOR, L3_DELAY_CEIL]。

状态机：calm → wary → backoff → cooldown →（恢复）calm；任一状态连续阻断
≥ L3_BLOCK_SUSPEND_THRESHOLD → suspended（终态，仅可由新会话重置）。

用法（L3 工具内）：
    ctrl = DisturbanceController(host, settings)
    async with ctrl.slot():            # 内含自适应延迟 + 冷却等待
        status, _, body = await run_sync(http_get, url)
    ctrl.observe(status, elapsed_ms=..., body_snippet=body[:200])
    # slot() 在 suspended 状态抛 DisturbanceSuspendedError → 工具捕获后转下一主机
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Optional

from utils.logger import audit

# 阻断页特征（与指纹引擎"阻断页面"识别同源语义；仅用于调速判定，不影响结果语义）
_BLOCK_HINTS: tuple[str, ...] = ("阻断页面", "访问被拒绝", "blocked", "captcha",
                                 "forbidden", "waf", "rate limit")

_STATES = ("calm", "wary", "backoff", "cooldown", "suspended")


class DisturbanceSuspendedError(RuntimeError):
    """HARD：主机已熔断（连续阻断），工具必须停止该主机采样并记录损失。"""


class DisturbanceController:
    """每主机一个实例：自适应延迟 + 冷却 + 熔断（asyncio 单线程语义）。"""

    def __init__(self, host: str, settings, *,
                 floor: tuple[float, float] | None = None,
                 ceil: tuple[float, float] | None = None) -> None:
        self.host = host
        self._floor = floor or settings.L3_DELAY_FLOOR
        self._ceil = ceil or settings.L3_DELAY_CEIL
        self._cooldown_range = settings.L3_COOLDOWN_RANGE
        self._block_threshold = settings.L3_BLOCK_SUSPEND_THRESHOLD
        self._rtt_factor = settings.L3_RTT_DOUBLE_FACTOR
        self._relax_streak = settings.L3_SUCCESS_RELAX_STREAK
        self._sem = asyncio.Semaphore(1)          # HARD: per-host 串行
        self._state = "calm"
        self._delay: float = self._floor[0]
        self._cooldown_until = 0.0
        self._block_streak = 0
        self._success_streak = 0
        self._rtt_baseline: Optional[float] = None
        self.requests = 0
        self.backoffs = 0
        self.suspend_reason = ""

    # ---------- 对外 ----------
    @property
    def state(self) -> str:
        return self._state

    def is_suspended(self) -> bool:
        return self._state == "suspended"

    def slot(self) -> "_DisturbSlot":
        """限速槽（语义同 StealthRateLimiter）：自适应延迟 + 冷却等待 + 熔断拦截。

        用法：`async with ctrl.slot(): ...`；suspended 状态直接抛
        DisturbanceSuspendedError（工具捕获后转下一主机）。
        """
        if self._state == "suspended":  # HARD: 熔断后拒绝一切请求
            raise DisturbanceSuspendedError(f"{self.host} 已熔断: {self.suspend_reason}")
        return _DisturbSlot(self)

    def observe(self, status: int, *, elapsed_ms: float = 0.0,
                retry_after: float | None = None, body_snippet: str = "") -> None:
        """每次响应后上报（status=0 表示连接层失败；只调节奏，不改变结果语义）。"""
        self.requests += 1
        lowered = body_snippet.lower()
        blocked = (status in (429, 503)
                   or (status in (403, 405) and any(h in lowered for h in _BLOCK_HINTS)))
        if retry_after:
            self._enter_cooldown(retry_after)
        elif blocked:
            self._on_block(status)
        elif status == 0:
            self._on_connect_failure()
        elif 200 <= status < 400:
            self._on_success(elapsed_ms)
        # 4xx/5xx 非阻断型 = 答案（WhatWeb 式），不触发退避也不重置计数

    def stats(self) -> dict:
        """扰动台账（进报告：请求数/退避次数/熔断原因）。"""
        return {"host": self.host, "state": self._state, "requests": self.requests,
                "backoffs": self.backoffs, "suspend_reason": self.suspend_reason,
                "current_delay": round(self._delay, 2)}

    # ---------- 状态迁移 ----------
    def _on_success(self, elapsed_ms: float) -> None:
        self._block_streak = 0
        self._success_streak += 1
        # RTT 基线：首次成功定基线；翻倍 → wary（潜在限速前兆，先不退避）
        if elapsed_ms > 0:
            if self._rtt_baseline is None:
                self._rtt_baseline = elapsed_ms
            elif elapsed_ms > self._rtt_baseline * self._rtt_factor and self._state == "calm":
                self._set_state("wary")
                self._delay = min(self._delay * 1.5, self._ceil[1])
        # 连续成功 → 向 floor 收敛（每 relax_streak 步 ×0.8）
        if (self._state in ("wary", "backoff")
                and self._success_streak >= self._relax_streak):
            self._delay = max(self._delay * 0.8, self._floor[0])
            if self._delay <= self._floor[0]:
                self._set_state("calm")
            self._success_streak = 0

    def _on_block(self, status: int) -> None:
        self._success_streak = 0
        self._block_streak += 1
        self.backoffs += 1
        if self._block_streak >= self._block_threshold:  # HARD: 熔断
            self._suspend(f"连续 {self._block_streak} 次阻断信号（最后 HTTP {status}）")
            return
        self._set_state("backoff")
        self._delay = min(max(self._delay * 2, self._floor[0]), self._ceil[1])

    def _on_connect_failure(self) -> None:
        # 连接层失败视为轻信号：不升级状态，但重置收敛计数（答案语义不变）
        self._success_streak = 0

    def _enter_cooldown(self, seconds: float) -> None:
        self._set_state("cooldown", cooldown_seconds=max(seconds, 1.0))

    def _suspend(self, reason: str) -> None:
        self._set_state("suspended")
        self.suspend_reason = reason
        audit("disturbance_suspend", {"host": self.host, "reason": reason})

    def _set_state(self, state: str, cooldown_seconds: float | None = None) -> None:
        if state in _STATES and state != self._state:
            self._state = state
            if state == "cooldown":
                wait = cooldown_seconds if cooldown_seconds is not None \
                    else random.uniform(*self._cooldown_range)
                self._cooldown_until = time.monotonic() + wait


class _DisturbSlot:
    """异步上下文：进入时等待（自适应延迟/冷却），持有 per-host 信号量。"""

    def __init__(self, ctrl: DisturbanceController):
        self._ctrl = ctrl

    async def __aenter__(self):
        await self._ctrl._sem.acquire()
        try:
            if self._ctrl._state == "cooldown":
                remaining = self._ctrl._cooldown_until - time.monotonic()
                if remaining > 0:
                    await asyncio.sleep(remaining)
                self._ctrl._set_state("backoff" if self._ctrl._delay > self._ctrl._floor[0]
                                      else "calm")
            if self._ctrl._delay > 0:
                await asyncio.sleep(random.uniform(self._ctrl._floor[0], max(
                    self._ctrl._delay, self._ctrl._floor[0])))
            return self
        except BaseException:
            self._ctrl._sem.release()
            raise

    async def __aexit__(self, *exc) -> None:
        self._ctrl._sem.release()
