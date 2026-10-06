"""builtin DNS 查询（L0 纯被动：DoH 公共解析 API + socket 兜底，绝不触碰目标）。"""
from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import urllib.request
from typing import Literal

from pydantic import BaseModel, Field

from security.stealth import StealthRateLimiter, random_user_agent
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings

DOH_RESOLVERS = (  # 降级链：google → 阿里（不同网络环境可达性不同，HARD：失败不重试只换源）
    ("dns.google", "https://dns.google/resolve"),
    ("dns.alidns.com", "https://dns.alidns.com/resolve"),
)
RTYPE_CODES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "SOA": 6, "CNAME": 5}
_LAST_GOOD_RESOLVER: str | None = None  # 进程内记忆最近成功解析器（性能优化，非安全相关）


class DNSParams(BaseModel):
    """DNS 记录查询参数。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="域名（纯被动查询公共 DNS）")
    rtype: Literal["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"] = "A"


class DNSQueryTool(BaseTool):
    """DNS 全记录查询：向公共 DoH 发起查询（目标是第三方解析器，非目标主机）。"""

    name = "dns_query"
    description = "查询域名 A/MX/NS/TXT/SOA 等公开 DNS 记录（纯被动 L0）"
    risk_level = "低"
    min_level = 0
    params_model = DNSParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.L0_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """DoH 查询（多解析器降级链）；全部失败再降级 socket.gethostbyname。"""
        assert isinstance(params, DNSParams)
        async with self._limiter.slot():
            try:
                raw, resolver = await asyncio.to_thread(self._doh_fetch, params.target, params.rtype)
            except (OSError, KeyError, json.JSONDecodeError, ValueError) as exc:
                return await self._fallback_socket(params.target, exc)
        data = json.loads(raw)
        answers = [
            {"name": a.get("name"), "type": a.get("type"), "data": a.get("data")}
            for a in data.get("Answer", [])
        ]
        return ToolResult(
            name=self.name,
            success=True,
            data={"target": params.target, "rtype": params.rtype,
                  "records": answers, "resolver": resolver},
            evidence=[f"DoH {resolver}: {params.target} {params.rtype} x{len(answers)}"],
            source_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64],  # HARD
            confidence=0.9,
        )

    def _doh_fetch(self, name: str, rtype: str) -> tuple[str, str]:
        """同步 DoH 请求（线程池中执行）：最近成功的解析器优先（性能优化）。"""
        import tools.builtin.dns_query as _mod

        last_exc: Exception | None = None
        order = sorted(DOH_RESOLVERS, key=lambda r: r[0] != _mod._LAST_GOOD_RESOLVER)
        for resolver, base in order:
            try:
                target_url = f"{base}?name={name}&type={RTYPE_CODES.get(rtype, 1)}"
                if not target_url.startswith(("http://", "https://")):  # HARD: 仅 http(s)
                    raise ValueError(f"仅允许 http(s) URL: {target_url[:60]}")
                req = urllib.request.Request(
                    target_url, headers={"User-Agent": random_user_agent()},
                )
                with urllib.request.urlopen(req, timeout=self._settings.CONNECT_TIMEOUT) as resp:
                    _mod._LAST_GOOD_RESOLVER = resolver
                    return resp.read().decode("utf-8", errors="replace"), resolver
            except (OSError, ValueError) as exc:
                last_exc = exc
        raise last_exc if last_exc else OSError("无可用 DoH 解析器")

    async def _fallback_socket(self, target: str, exc: Exception) -> ToolResult:
        """DoH 不可达 → socket 系统解析（仅 A 记录，HARD 标注降级）。"""
        try:
            _, _, ips = await asyncio.to_thread(socket.gethostbyname_ex, target)
        except (OSError, UnicodeError):
            return ToolResult.err(self.name, f"DNS 查询失败: {exc}（失败不重试）")
        return ToolResult(
            name=self.name,
            success=True,
            data={"target": target, "rtype": "A", "records": [{"data": ip} for ip in ips],
                  "resolver": "socket(系统)", "note": str(exc)[:120]},
            evidence=[f"socket.gethostbyname: {target} -> {','.join(ips)}"],
            confidence=0.6,
            degraded=True,  # HARD
        )
