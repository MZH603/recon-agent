"""builtin L3 存活探测 + OS 启发式：ICMP Echo ×1 / TTL→OS 判定 / TCP connect 兜底。

对应用户矩阵第二阶段：
- 「存活主机：ICMP Echo (Ping)、TCP SYN/ACK 扫描」→ L1 已有 TCP 端口面确认，
  此处补 ICMP Echo 存活判定 + TCP 80/443 兜底（ICMP 被墙 ≠ 主机不存活）；
- 「操作系统识别：分析 TCP/IP 协议栈实现差异 (TTL, Window Size 等)」→ 用 ICMP
  应答 TTL 启发式（≤64 Unix-like / 65-128 Windows / >128 网络设备）。

HARD 纪律：
- 仅对授权范围内主机（子域枚举+端口面已确认的 alive 列表），禁止 C 段存活扫
  （范围外资产不触碰，HARD）；
- 每主机 ICMP ×1（2s 超时）；ICMP 无应答时 TCP connect 80/443 各 1 次（共 ≤3 连接/主机）；
- cap=ALIVE_PROBE_CAP；并发由 ALIVE_PROBE_CONCURRENCY 限（默认 5）；
- 系统原生 ping（Windows ping -n / Unix ping -c），无原始套接字、无需管理员权限。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import platform as _platform
import re
import socket

from pydantic import BaseModel, Field

from utils.config import Settings, get_settings

from tools.base import BaseTool, ToolResult

TTL_WINDOWS = r"[Tt][Tt][Ll][=:]?\s*(\d+)"
TTL_UNIX = re.compile(r"ttl[=:]\s*(\d+)", re.I)


def parse_ping_output(output: str) -> tuple[bool, int]:
    """纯函数：ping 命令输出 → (是否存活应答, TTL)（无 TTL 字段时 TTL=0）。

    判定依据：出现 TTL 字段 = 收到 ICMP Echo Reply；无 TTL（如 "Request timed
    out"/"100% packet loss"/"Destination host unreachable"）= 不存活。
    """
    match = TTL_UNIX.search(output)
    if match:
        return True, int(match.group(1))
    return False, 0


def ttl_to_os(ttl: int) -> str:
    """纯函数：ICMP 应答 TTL → OS 启发式判定（128 基线 → Windows；64 基线 → Unix-like）。"""
    if ttl <= 0:
        return "未知"
    if ttl <= 64:
        return "Unix-like（TTL≤64）"
    if ttl <= 128:
        return "Windows（TTL≤128）"
    return "网络设备（TTL≤255）"


def build_ping_args(host: str) -> list[str]:
    """纯函数：平台 → ping 参数（单次 echo，2s 超时）。"""
    if _platform.system() == "Windows":
        return ["ping", "-n", "1", "-w", "2000", "-4", host]
    return ["ping", "-c", "1", "-W", "2", host]


class AliveOsProbeParams(BaseModel):
    """存活探测参数（hosts 仅限授权范围内主机）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="授权主域名（审计记录用）")
    hosts: list[str] = Field(..., min_length=1, max_length=100,
                             description="待探测主机（授权范围内；禁止任意 C 段）")


class AliveOsProbeTool(BaseTool):
    """L3 存活探测 + OS 启发式（ICMP ×1 / TTL 判定 / TCP 兜底）。"""

    name = "alive_os_probe"
    description = ("ICMP Echo ×1 存活判定 + TTL→OS 启发式 + TCP 80/443 兜底"
                   "（仅授权范围内主机，每主机 ≤3 连接，L3）")
    risk_level = "中"
    min_level = 3
    params_model = AliveOsProbeParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, AliveOsProbeParams)
        hosts = list(dict.fromkeys(params.hosts))[: self._settings.ALIVE_PROBE_CAP]  # HARD cap
        notes: list[str] = []
        sem = asyncio.Semaphore(self._settings.ALIVE_PROBE_CONCURRENCY)
        results: list[dict] = []

        async def one(host: str) -> None:
            async with sem:
                entry = {"host": host, "icmp": False, "ttl": 0, "os_guess": "未知",
                         "tcp_fallback": False}
                try:
                    ret, out, _err = await self._ping(host)
                except (OSError, ValueError) as exc:
                    notes.append(f"{host}: ping 执行异常 {type(exc).__name__}（不重试）")
                    ret, out = 1, ""
                icmp_alive, ttl = parse_ping_output(out)
                if icmp_alive:
                    entry.update(icmp=True, ttl=ttl, os_guess=ttl_to_os(ttl))
                else:
                    # ICMP 无应答 → TCP 80/443 兜底（ICMP 被墙 ≠ 不存活）
                    for port in (80, 443):
                        if await self._tcp_alive(host, port):
                            entry["tcp_fallback"] = True
                            entry["os_guess"] = "ICMP 被过滤，TCP 存活（OS 未判定）"
                            break
                results.append(entry)

        await asyncio.gather(*[one(h) for h in hosts], return_exceptions=True)
        alive_icmp = [r for r in results if r["icmp"]]
        alive_tcp = [r for r in results if r["tcp_fallback"] and not r["icmp"]]
        unreachable = [r["host"] for r in results if not r["icmp"] and not r["tcp_fallback"]]

        data = {
            "target": params.target,
            "probed": len(hosts),
            "alive_icmp": alive_icmp,
            "alive_tcp_only": [r["host"] for r in alive_tcp],
            "unreachable": unreachable,
            "os_guesses": {r["host"]: r["os_guess"] for r in alive_icmp},
            "notes": notes,
        }
        evidence = [
            f"存活探测: {len(hosts)} 主机 → ICMP 应答 {len(alive_icmp)}"
            f"，仅 TCP 存活 {len(alive_tcp)}，均无应答 {len(unreachable)}",
            "OS 启发式: TTL≤64 Unix-like / TTL≤128 Windows / >128 网络设备（需人工核实）",
            "HARD：仅授权范围内主机；ICMP ×1 + TCP 兜底 ≤2 连接/主机",
        ] + notes
        return ToolResult(
            name=self.name, success=bool(alive_icmp or alive_tcp),
            data=data, evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.65 if alive_icmp else (0.4 if alive_tcp else 0.3),
        )

    async def _ping(self, host: str) -> tuple[int, str, str]:
        """系统 ping ×1（run_command 封装，10s 上限防挂起）。"""
        from platforms.subprocess import run_command
        return await run_command(build_ping_args(host), timeout=10)

    async def _tcp_alive(self, host: str, port: int) -> bool:
        """TCP connect 兜底（1 次连接，2s 超时）。"""

        def _sync() -> bool:
            try:
                with socket.create_connection((host, port), timeout=2.0):
                    return True
            except OSError:
                return False

        try:
            return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=4.0)
        except asyncio.TimeoutError:
            return False
