"""nmap 适配器（HARD：仅 TCP Connect + 限速；nmap 缺失自动降级 builtin socket 并标注）。"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from platforms.subprocess import run_command
from platforms.tools import find_tool
from security.stealth import enforce_stealth
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings


class PortScanParams(BaseModel):
    """端口扫描参数（HARD：Schema 硬化——枚举穷举 + 范围约束）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机/域名/IP")
    ports: str = Field("80,443", description="端口列表，最多20个，如 80,443,8080")
    scan_type: Literal["tcp_connect"] = "tcp_connect"  # HARD: 仅允许 TCP Connect
    max_rate: int = Field(1, ge=1, le=2)               # HARD: 限速

    @field_validator("ports")
    @classmethod
    def _cap_ports(cls, v: str) -> str:
        """最多 20 个端口（HARD：禁止无差别全端口爆破）。"""
        ports = [p for p in re.split(r"[,]", v.strip()) if p]
        if not ports or len(ports) > 20 or not all(p.isdigit() or "-" in p for p in ports):
            raise ValueError("ports 必须形如 80,443 或 80-90，且最多 20 个")
        return ",".join(ports)


class NmapTool(BaseTool):
    """nmap 隐蔽端口扫描（L1）：强制 NMAP_ARGS_SAFE，参数越限自动修正。"""

    name = "nmap_scan"
    description = "对目标做隐蔽 TCP Connect 端口扫描（限速，最多20端口）"
    risk_level = "中"
    min_level = 1
    params_model = PortScanParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        """优先 nmap；缺失时降级 builtin socket（置信度下调一档）。"""
        assert isinstance(params, PortScanParams)
        nmap = find_tool("nmap")
        if not nmap:
            from tools.builtin.port_scan import BuiltinPortScan

            # HARD: 降级实现使用自己的参数契约（显式转换，避免跨 Schema 断言失败）
            fallback_params = BuiltinPortScan.params_model(
                target=params.target, ports=params.ports, max_rate=params.max_rate
            )
            result = await BuiltinPortScan(self._settings).run(fallback_params)
            result.degraded = True  # HARD: 降级必须标注
            result.confidence = min(result.confidence, 0.6)
            result.evidence.append("[降级模式] nmap 不可用 → builtin_socket（端口覆盖下降）")
            return result
        args, corrections = enforce_stealth(
            "nmap", [nmap, "-p", params.ports, params.target], self._settings
        )
        ret, out, err = await run_command(args, timeout=300)
        if ret != 0:
            return ToolResult.err(self.name, f"nmap 退出码 {ret}: {err[:300]}（失败不重试，HARD）")
        open_ports = re.findall(r"^(\d+)/tcp\s+open", out, re.M)
        return ToolResult(
            name=self.name,
            success=True,
            stdout=out[:2000],
            data={"open_ports": [int(p) for p in open_ports], "ports_requested": params.ports,
                  "corrections": corrections},
            evidence=[f"nmap {' '.join(args[1:5])}..."] if not corrections else
                     [f"nmap {' '.join(args[1:5])}...", *[f"[修正] {c}" for c in corrections]],
            confidence=0.9,
        )
