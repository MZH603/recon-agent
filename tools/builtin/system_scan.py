"""系统安全工具网关（L2 门控）：Agent 通过白名单调用系统安全工具。

HARD:
- 仅允许 SECURITY_TOOL_DB 白名单中的工具
- 强制注入隐蔽参数（限速/TCP Connect/安全 flags）
- L2 门控（三次确认+签名+逐项确认）
- 超时强杀 · 审计留痕
"""
from __future__ import annotations

import asyncio
import re

from pydantic import BaseModel, Field, field_validator

from core.tool_discovery import discover_system_tools
from platforms.subprocess import run_command
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings
from utils.logger import audit

# 工具命令模板（{target} 占位符由调用方替换；安全参数强制注入）
COMMAND_TEMPLATES: dict[str, list[str]] = {
    "nmap": ["nmap", "-sT", "--max-rate", "1", "--max-parallelism", "1",
             "-p", "{ports}", "{target}"],
    "whatweb": ["whatweb", "-q", "--no-errors", "{target}"],
    "curl": ["curl", "-sS", "-o", "/dev/null", "-w",
             "%{http_code} %{redirect_url}", "-m", "10",
             "-H", "User-Agent: Mozilla/5.0", "{target}"],
    "httpx": ["httpx", "-u", "{target}", "-silent", "-status-code", "-title",
              "-tech-detect", "-no-color"],
    "dig": ["dig", "{target}", "{rtype}"],
    "whois": ["whois", "{target}"],
    "whatweb_banner": ["whatweb", "-q", "{target}"],
}

# 允许通过网关执行的工具白名单（HARD）
ALLOWED_TOOLS = set(COMMAND_TEMPLATES.keys()) | {"whatweb_detail"}


class SystemScanParams(BaseModel):
    """系统工具调用参数。"""

    tool: str = Field(..., description="系统工具名（白名单校验）")
    target: str = Field(..., pattern=r"^[\w\.\-/:]+$")
    ports: str = Field("80,443,22", description="nmap 端口集")
    rtype: str = Field("A", description="DNS 记录类型（dig）")

    @field_validator("tool")
    @classmethod
    def _validate_tool(cls, v: str) -> str:
        if v not in ALLOWED_TOOLS:
            raise ValueError(f"工具 {v} 不在白名单中（允许: {sorted(ALLOWED_TOOLS)}）")
        return v


class SystemScanTool(BaseTool):
    """系统安全工具网关（L2）：优先使用系统已有工具进行探测。"""

    name = "system_scan"
    description = "调用系统安全工具（nmap/whatweb/curl/dig/whois 等）进行探测（白名单校验，L2）"
    risk_level = "高"
    min_level = 2
    params_model = SystemScanParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._available = discover_system_tools()

    async def run(self, params: BaseModel) -> ToolResult:
        """执行系统工具并解析输出。"""
        assert isinstance(params, SystemScanParams)
        tool_name = params.tool

        # 检查系统工具是否可用
        if tool_name not in self._available:
            available = ", ".join(sorted(self._available)) or "无"
            return ToolResult.err(self.name,
                                  f"[工具不可用] {tool_name} 未安装。可用工具: {available}")

        tool_path = self._available[tool_name].path
        template = COMMAND_TEMPLATES.get(tool_name)
        if not template:
            return ToolResult.err(self.name, f"[不支持] {tool_name} 无命令模板")

        # 构造命令
        cmd = [tool_path if i == 0 else t for i, t in enumerate(template)]
        cmd = [arg.replace("{target}", params.target)
                 .replace("{ports}", params.ports)
                 .replace("{rtype}", params.rtype)
              for arg in cmd]
        # 强制使用系统路径（安全：防止 PATH 劫持）
        cmd[0] = tool_path

        audit("system_scan", {"tool": tool_name, "target": params.target, "cmd": " ".join(cmd[:5])})

        # 执行（限速 + 超时）
        exit_code, stdout_text, stderr_text = await run_command(cmd, timeout=self._settings.CONNECT_TIMEOUT * 3)

        return ToolResult(
            name=self.name,
            success=(exit_code == 0),
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
            data={"tool": tool_name, "target": params.target, "raw_output": stdout_text},
            evidence=[f"系统工具 {tool_name}: {' '.join(cmd[:3])}..."],
            confidence=0.9,
            status='timeout' if exit_code == 124 else ('success' if exit_code == 0 else 'failure'),
            error_code='TOOL_TIMEOUT' if exit_code == 124 else '',
            error=stderr_text if exit_code else '',
            outcome_unknown='outcome unknown' in stderr_text,
        )
