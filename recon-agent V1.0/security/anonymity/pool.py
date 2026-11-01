"""代理 IP 池（HARD：线程安全；健康状态与轮换策略集中管理；操作全量审计）。

轮换语义（rotation）：
- sticky     同一目标键固定同一出口（防 IP 抖动关联指纹），目标间轮换（默认）；
- round_robin 严格顺序轮转；
- random     加权随机。
失败出口进入冷却期（fail_cooldown_seconds），冷却结束自动回归候选。
"""
from __future__ import annotations

import hashlib
import random
import threading
import time

from security.anonymity.config import (
    DEFAULT_PROBE_URL,
    PROBE_MAX_CONCURRENCY,
    PROBE_TIMEOUT_SECONDS,
    ProxyEndpoint,
    RotationStrategy,
)
from security.anonymity import tunnel
from utils.logger import audit

_HEALTH_TTL_FACTOR: float = 2.0   # 惰性健康检查窗口 = health_interval × 该系数


class _EndpointState:
    __slots__ = ("endpoint", "failures", "latency_ms", "cooldown_until", "last_check")

    def __init__(self, endpoint: ProxyEndpoint) -> None:
        self.endpoint = endpoint
        self.failures: int = 0
        self.latency_ms: float = -1.0
        self.cooldown_until: float = 0.0
        self.last_check: float = 0.0

    def is_available(self, now: float) -> bool:
        return now >= self.cooldown_until

    @property
    def healthy_score(self) -> float:
        """健康分：冷却越近、失败越多分越低；延迟未知记 0 惩罚。"""
        base = 1.0 / (1.0 + self.failures)
        latency = self.latency_ms if self.latency_ms >= 0 else 0.0
        return base + max(0.0, 1000.0 - latency) / 1000.0


class ProxyPool:
    """出口池：acquire → 用完 report_success / report_failure。"""

    def __init__(self, endpoints: list[ProxyEndpoint], rotation: RotationStrategy = "sticky",
                 fail_cooldown_seconds: int = 600, health_interval_seconds: int = 300,
                 probe_url: str = DEFAULT_PROBE_URL) -> None:
        self._lock = threading.Lock()
        self._states: list[_EndpointState] = [_EndpointState(ep) for ep in endpoints]
        self._rotation: RotationStrategy = rotation
        self._cooldown = fail_cooldown_seconds
        self._health_interval = health_interval_seconds
        self._probe_url = probe_url
        self._rr_index = 0
        self._sticky_map: dict[str, int] = {}

    # ---- 选择 ----

    def acquire(self, target_key: str = "") -> ProxyEndpoint | None:
        """按策略选一个当前可用出口；池空/全部冷却返回 None（调用方须 fail closed）。"""
        now = time.time()
        with self._lock:
            candidates = [st for st in self._states if st.is_available(now)]
            if not candidates:
                audit("pool_exhausted", {"total": len(self._states)})
                return None
            if self._rotation == "round_robin":
                # 顺序推进到第一个可用项
                for _ in range(len(self._states)):
                    idx = self._rr_index % len(self._states)
                    self._rr_index += 1
                    state = self._states[idx]
                    if state.is_available(now):
                        return state.endpoint
                return None
            if self._rotation == "random":
                state = random.choices(candidates, weights=[c.endpoint.weight for c in candidates])[0]
                return state.endpoint
            # sticky：目标哈希稳定映射；映射失效（出口冷却）时顺延重映射
            digest = hashlib.sha256(target_key.encode("utf-8", "replace")).digest()
            offset = int.from_bytes(digest[:8], "big")
            if target_key in self._sticky_map:
                state = self._states[self._sticky_map[target_key]]
                if state.is_available(now):
                    return state.endpoint
            chosen = candidates[offset % len(candidates)]
            self._sticky_map[target_key] = self._states.index(chosen)
            return chosen.endpoint

    def healthy_count(self) -> int:
        now = time.time()
        with self._lock:
            return sum(1 for st in self._states if st.is_available(now))

    def total_count(self) -> int:
        with self._lock:
            return len(self._states)

    # ---- 反馈 ----

    def report_success(self, endpoint: ProxyEndpoint, latency_ms: float = -1.0) -> None:
        with self._lock:
            state = self._find(endpoint)
            if state:
                state.failures = 0
                state.cooldown_until = 0.0
                state.last_check = time.time()
                if latency_ms >= 0:
                    state.latency_ms = latency_ms if state.latency_ms < 0 else state.latency_ms * 0.7 + latency_ms * 0.3

    def report_failure(self, endpoint: ProxyEndpoint) -> None:
        with self._lock:
            state = self._find(endpoint)
            if not state:
                return
            state.failures += 1
            # HARD：连续失败进入冷却，期间 acquire 不可见（防半死出口拖慢流量并暴露特征）
            state.cooldown_until = time.time() + self._cooldown
            audit("proxy_cooldown", {"url": _mask(endpoint.url), "failures": state.failures,
                                     "cooldown_seconds": self._cooldown})

    def _find(self, endpoint: ProxyEndpoint) -> _EndpointState | None:
        for state in self._states:
            if state.endpoint.url == endpoint.url:
                return state
        return None

    # ---- 健康检查 ----

    def check_health(self, timeout: float = PROBE_TIMEOUT_SECONDS) -> int:
        """同步逐端点探测 probe_url；返回仍健康数量（惰性触发，不在请求路径上）。

        HARD：探测走代理本身（验证完整隧道），不探测目标；失败记冷却。
        """
        import urllib.error
        import urllib.request
        now = time.time()
        healthy = 0
        for state in list(self._states):
            with self._lock:
                if now - state.last_check < self._health_interval / _HEALTH_TTL_FACTOR:
                    healthy += 1 if state.is_available(now) else 0
                    continue
            started = time.monotonic()
            ok = False
            try:
                opener = self._probe_opener(state.endpoint)
                with opener.open(self._probe_url, timeout=timeout) as resp:
                    ok = 200 <= resp.status < 400
            except (OSError, ValueError, urllib.error.HTTPError):
                ok = False
            latency = (time.monotonic() - started) * 1000.0
            if ok:
                self.report_success(state.endpoint, latency)
                healthy += 1
            else:
                self.report_failure(state.endpoint)
        return healthy

    @staticmethod
    def _probe_opener(endpoint: ProxyEndpoint):
        """探测 opener：SOCKS5 用隧道 socket，HTTP(S) 代理用 ProxyHandler。"""
        from security.anonymity.egress import opener_for_proxy
        return opener_for_proxy(endpoint.url)


def _mask(url: str) -> str:
    """审计脱敏：隐藏代理 URL 中的凭据。"""
    try:
        import urllib.parse
        parts = urllib.parse.urlsplit(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        return f"{parts.scheme}://{netloc}"
    except ValueError:
        return "<malformed-proxy-url>"


def probe_endpoint(endpoint: ProxyEndpoint, probe_url: str = DEFAULT_PROBE_URL,
                   timeout: float = PROBE_TIMEOUT_SECONDS) -> tuple[bool, float]:
    """单端点探测（doctor 用）：返回 (是否健康, 延迟 ms)。HARD：并发探测调用方限 2。"""
    import urllib.error
    import urllib.request
    started = time.monotonic()
    try:
        from security.anonymity.egress import opener_for_proxy
        with opener_for_proxy(endpoint.url).open(probe_url, timeout=timeout) as resp:
            ok = 200 <= resp.status < 400
    except (OSError, ValueError, urllib.error.HTTPError):
        return False, -1.0
    return ok, (time.monotonic() - started) * 1000.0


PROBE_LIMITS = (PROBE_MAX_CONCURRENCY, PROBE_TIMEOUT_SECONDS)  # 供 doctor 展示
