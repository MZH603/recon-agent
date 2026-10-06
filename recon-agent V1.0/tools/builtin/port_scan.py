"""builtin 端口扫描（nmap 降级实现；HARD：单线程、限速、失败即停、禁异常 packets）。"""
from __future__ import annotations

import asyncio
import re

from pydantic import BaseModel, Field, field_validator

from security.stealth import StealthRateLimiter, normalize_host
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings


class BuiltinScanParams(BaseModel):
    """与 NmapTool 相同的参数契约（降级实现保持 Schema 一致）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$")
    ports: str = Field("80,443", description="端口列表，最多20个")
    scan_type: str = Field("tcp_connect", pattern=r"^tcp_connect$")  # HARD: 仅 TCP Connect
    max_rate: int = Field(1, ge=1, le=2)

    @field_validator("ports")
    @classmethod
    def _cap_ports(cls, v: str) -> str:
        ports = [p for p in re.split(r"[,]", v.strip()) if p]
        if not ports or len(ports) > 20 or not all(p.isdigit() or "-" in p for p in ports):
            raise ValueError("ports 必须形如 80,443 或 80-90，且最多 20 个")
        return ",".join(ports)


class BuiltinPortScan(BaseTool):
    """socket TCP Connect 扫描（L1）：纯 Connect 无异常包，超时即停（HARD 失败不重试）。"""

    name = "builtin_port_scan"
    description = "socket 逐端口 TCP Connect 探测（nmap 降级实现，限速单线程）"
    risk_level = "中"
    min_level = 1
    params_model = BuiltinScanParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        # HARD: L1/L2 间隔随机 3-10s；测试可注入更短区间
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.REQUEST_DELAY_RANGE,
            self._settings.MAX_CONCURRENCY,
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """逐端口 Connect：refused=关闭（这是答案不是失败）；timeout=失败→立即停止。"""
        assert isinstance(params, BuiltinScanParams)
        host = normalize_host(params.target)
        open_ports: list[int] = []
        closed: list[int] = []
        stopped_early = False
        evidence: list[str] = []
        for port in _expand(params.ports):
            async with self._limiter.slot():
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self._settings.CONNECT_TIMEOUT,
                    )
                    open_ports.append(port)
                    writer.close()
                    evidence.append(f"tcp/{port} open (TCP Connect)")
                except ConnectionRefusedError:
                    closed.append(port)
                except (asyncio.TimeoutError, OSError) as exc:
                    # HARD: 连接超时/异常 → 立即停止对该目标的主动探测，禁止重试
                    stopped_early = True
                    evidence.append(f"tcp/{port} 探测失败({type(exc).__name__}) → 已停止，不重试")
                    break
        return ToolResult(
            name=self.name,
            success=True,
            data={"open_ports": open_ports, "closed": closed, "stopped_early": stopped_early},
            evidence=evidence or ["无端口探测完成"],
            confidence=0.7,
            degraded=True,  # builtin 相对 nmap 恒为降级模式（HARD 标注）
        )


def _expand(spec: str) -> list[int]:
    """展开 '80,443,8000-8002' 为端口列表（上限 20）。"""
    ports: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return ports[:20]
