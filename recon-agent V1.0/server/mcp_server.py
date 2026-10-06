"""最小 MCP（Model Context Protocol）stdio 服务器——零新增依赖（HARD：核心依赖 ≤5）。

协议：stdin/stdout 上的换行分隔 JSON-RPC 2.0；支持
initialize / notifications/initialized / tools/list / tools/call / ping。
供 Claude Desktop、ZCode、Cline 等第三方 AI Agent 自主接入调用。

HARD：
- stdout 只承载协议帧，所有日志/审计走 stderr 与审计文件（utils.logger.set_stderr_mode）；
- MCP 为非交互模式 → L2 永久禁止；L1 需启动参数 --allow-l1 显式放行；
- 必须以 --authorized-for 声明授权范围，否则拒绝启动。

运行：recon-agent-mcp --authorized-for example.com --allow-l1
  或：python -m server.mcp_server --authorized-for example.com
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # 允许 python server/mcp_server.py 直接运行
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.tools_bridge import MCPBridge  # noqa: E402
from utils.config import Settings, get_settings  # noqa: E402
from utils.logger import audit, set_stderr_mode, warn  # noqa: E402

PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
SERVER_INFO = {"name": "recon-agent", "version": "1.0.0"}


class MCPProtocol:
    """JSON-RPC 2.0 消息处理（与传输解耦，便于单元测试）。"""

    def __init__(self, bridge: MCPBridge) -> None:
        self._bridge = bridge

    async def handle(self, message: dict) -> dict | None:
        """处理一条入站消息；通知类返回 None（不回应）。"""
        method = message.get("method", "")
        msg_id = message.get("id")
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion", "2024-11-05")
            version = requested if requested in PROTOCOL_VERSIONS else "2024-11-05"
            return _result(msg_id, {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            })
        if method.startswith("notifications/"):
            return None
        if method == "ping":
            return _result(msg_id, {})
        if method == "tools/list":
            return _result(msg_id, {"tools": self._bridge.tool_schemas()})
        if method == "tools/call":
            params = message.get("params") or {}
            try:
                text, is_error = await self._bridge.call(
                    str(params.get("name", "")), dict(params.get("arguments") or {})
                )
            except Exception as exc:  # noqa: BLE001 —— 任何异常收敛为 isError 结果
                text, is_error = f"[内部错误] {exc}", True
            return _result(msg_id, {"content": [{"type": "text", "text": text}],
                                    "isError": is_error})
        if msg_id is not None:
            return _error(msg_id, -32601, f"未知方法: {method}")
        return None


async def serve(authorized_for: list[str], allow_l1: bool = False,
                settings: Settings | None = None) -> int:
    """stdio 主循环（跨平台：阻塞 readline 放线程池，兼容 Windows Proactor）。"""
    set_stderr_mode()  # HARD: stdout 只承载协议
    _force_utf8_stdio()
    settings = settings or get_settings()
    roots = [r.strip() for r in authorized_for if r.strip()]
    if not roots:
        print("[mcp] 启动失败：必须 --authorized-for <域名,域名> 声明授权范围（HARD）", file=sys.stderr)
        return 2
    protocol = MCPProtocol(MCPBridge(settings, roots, allow_l1))
    audit("mcp_server_start", {"roots": roots, "allow_l1": allow_l1})
    warn(f"[mcp] recon-agent V1.0 MCP 服务器就绪（授权范围: {', '.join(roots)}，L1={'允许' if allow_l1 else '禁止'}）")
    while True:
        line = await asyncio.to_thread(sys.stdin.readline)
        if not line:
            return 0  # EOF：客户端断开
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            warn(f"[mcp] 非 JSON 帧（忽略）: {exc}")
            continue
        response = await protocol.handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    """独立入口（recon-agent-mcp / python -m server.mcp_server）。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    roots: list[str] = []
    allow_l1 = False
    i = 0
    while i < len(argv):
        if argv[i] == "--authorized-for" and i + 1 < len(argv):
            roots = [x for x in argv[i + 1].split(",") if x.strip()]
            i += 2
        elif argv[i] == "--allow-l1":
            allow_l1 = True
            i += 1
        else:
            print(f"[mcp] 未知参数 {argv[i]}（支持 --authorized-for / --allow-l1）", file=sys.stderr)
            return 2
    return asyncio.run(serve(roots, allow_l1))


def _force_utf8_stdio() -> None:
    """Windows 控制台默认 GBK：协议通道强制 UTF-8（HARD：跨平台一致）。"""
    for stream in (sys.stdout, sys.stdin):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass


def _result(msg_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


if __name__ == "__main__":
    raise SystemExit(main())
