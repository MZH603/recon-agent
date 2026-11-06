"""builtin L3 拓扑追踪：路由追踪（hop 链 + RTT），绘制目标可达路径。

对应用户矩阵第二阶段「网络拓扑/路由：路由追踪 (Traceroute)、分析跳数和延迟」。

HARD 纪律：
- 用系统原生 tracert（Windows）/ traceroute→tracepath 降级链（Unix），
  无原始套接字、无需管理员权限；每主机 1 次执行；
- 跳数硬上限 TRACEROUTE_MAX_HOPS（-h/-m）；主机数硬上限 TRACEROUTE_HOST_CAP；
- 目标仅限授权范围内主机；-n/-d 不做反向解析（避免额外 DNS 流量）；
- 未经过 nmap（--traceroute 需原始套接字且白名单外），保持低扰动。
"""
from __future__ import annotations

import hashlib
import json
import platform as _platform
import re

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings

WIN_HOP_RE = re.compile(
    r"^\s*(\d{1,3})\s+(?:(\d+)\s*ms|\*)\s+(?:(\d+)\s*ms|\*)\s+(?:(\d+)\s*ms|\*)\s+([\w\.\-\[\]:]+)")
UNIX_HOP_RE = re.compile(r"^\s*(\d{1,3})\s+(?:([\w\.\-:]+)(?:\s+\(?([\d\.]+)\)?)?)?\s+([\d\.]+)\s*ms")
UNIX_TIMEOUT_RE = re.compile(r"^\s*(\d{1,3})\s+\*")
TRACEPATH_RE = re.compile(r"^\s*(\d{1,3}):\s+(no reply|[\w\.\-:]+)(?:\s+([\d\.]+)\s*ms)?")


def parse_tracert_windows(output: str, max_hops: int) -> list[dict]:
    """纯函数：Windows tracert -d 输出 → 跳链（超时跳标记 timeout；区域无关）。"""
    hops: list[dict] = []
    for line in output.splitlines():
        m = WIN_HOP_RE.match(line)
        if not m:
            continue
        hop_no = int(m.group(1))
        if hop_no > max_hops:
            break
        rtts = [int(g) for g in m.groups()[1:4] if g]
        addr = (m.group(5) or "").strip("[]")
        # 全 * 跳（"Request timed out"/"请求超时"）→ addr 一律收敛 timeout
        hops.append({
            "hop": hop_no, "addr": addr if rtts else "timeout",
            "rtt_ms": min(rtts) if rtts else None, "timeout": not rtts,
        })
    return hops


def parse_traceroute_unix(output: str, max_hops: int) -> list[dict]:
    """纯函数：Unix traceroute -n / tracepath -n 输出 → 跳链。"""
    hops: list[dict] = []
    for line in output.splitlines():
        if line.strip().startswith(("traceroute to", "tracepath to", "1?")):
            continue
        hop: dict | None = None
        m = UNIX_HOP_RE.match(line)
        if m and int(m.group(1)) <= max_hops:
            addr = m.group(2) or ""
            rtt = float(m.group(4)) if m.group(4) else None
            hop = {"hop": int(m.group(1)), "addr": addr or "timeout",
                   "rtt_ms": rtt, "timeout": addr in ("", "*")}
        else:
            m = TRACEPATH_RE.match(line)
            if m and int(m.group(1)) <= max_hops:
                addr = m.group(2) or ""
                hop = {"hop": int(m.group(1)),
                       "addr": "timeout" if addr in ("", "no reply") else addr,
                       "rtt_ms": float(m.group(3)) if m.group(3) else None,
                       "timeout": addr in ("", "no reply")}
            else:
                m = UNIX_TIMEOUT_RE.match(line)
                if m and int(m.group(1)) <= max_hops:
                    hop = {"hop": int(m.group(1)), "addr": "timeout",
                           "rtt_ms": None, "timeout": True}
        if hop:
            # 同一跳重试行（traceroute -q>1 输出多行同号）合并：首行地址优先
            existing = next((h for h in hops if h["hop"] == hop["hop"]), None)
            if existing is None:
                hops.append(hop)
            elif existing["timeout"] and not hop["timeout"]:
                existing.update(hop)
    return hops


def build_trace_args(host: str, max_hops: int) -> tuple[list[str], str] | None:
    """纯函数：平台 → 拓扑追踪参数（返回 (args, backend)；无可用后端返回 None）。"""
    system = _platform.system()
    if system == "Windows":
        return ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host], "tracert"
    # Unix：traceroute 优先（多数发行版需安装），降级 tracepath（iputils 预装）
    from platforms.tools import find_tool
    if find_tool("traceroute"):
        return ["traceroute", "-n", "-m", str(max_hops), "-w", "2", "-q", "1", host], "traceroute"
    if find_tool("tracepath"):
        return ["tracepath", "-n", "-m", str(max_hops), host], "tracepath"
    return None


class TopologyTraceParams(BaseModel):
    """拓扑追踪参数（单主机 1 次执行）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机（授权范围内）")
    max_hops: int = Field(15, ge=2, le=30, description="HARD ≤TRACEROUTE_MAX_HOPS")


class TopologyTraceTool(BaseTool):
    """L3 拓扑追踪（系统 tracert/traceroute/tracepath，跳数硬上限）。"""

    name = "topology_trace"
    description = ("路由追踪绘制可达路径（系统原生 tracert/traceroute/tracepath，"
                   "-h/-m 硬上限，每主机 1 次，无原始套接字，L3）")
    risk_level = "中"
    min_level = 3
    params_model = TopologyTraceParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, TopologyTraceParams)
        max_hops = min(params.max_hops, self._settings.TRACEROUTE_MAX_HOPS)  # HARD cap
        host = params.target.split(":")[0]  # 剥离 host:port（路由追踪只到主机）
        built = build_trace_args(host, max_hops)
        if built is None:
            return ToolResult.err(
                self.name, "无可用后端：tracert/traceroute/tracepath 均不可用（无降级，HARD）")
        args, backend = built
        from platforms.subprocess import run_command
        ret, out, err = await run_command(args, timeout=120)
        if ret != 0 and not out.strip():
            return ToolResult.err(
                self.name, f"{backend} 退出码 {ret}: {err[:200]}（失败不重试，HARD）")

        if backend == "tracert":
            hops = parse_tracert_windows(out, max_hops)
        else:
            hops = parse_traceroute_unix(out, max_hops)
        resolved = [h for h in hops if not h["timeout"]]
        data = {
            "target": host, "backend": backend, "max_hops": max_hops,
            "hops": hops, "hop_count": len(hops), "resolved_hops": len(resolved),
        }
        evidence = [
            f"拓扑追踪 ({backend}): {len(hops)} 跳，解析 {len(resolved)} 跳，"
            f"最终跳 {resolved[-1]['addr'] if resolved else '未解析'}",
            "HARD：跳数硬上限 + 每主机 1 次执行 + 无反向解析（-n/-d）",
        ]
        return ToolResult(
            name=self.name, success=bool(hops), data=data, evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.6 if resolved else 0.3,
        )
