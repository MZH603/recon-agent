"""httpx 适配器（L0 被动探活：单次只读 GET；httpx 缺失降级 builtin 指纹探测）。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from platforms.subprocess import run_command
from platforms.tools import find_tool
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings


class HttpxParams(BaseModel):
    """探活参数：单次 GET（HARD：不枚举路径、不爆破）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机或 URL")
    follow_redirects: bool = Field(False, description="是否跟随重定向（默认否，减少请求）")
    scope: Literal["main", "subdomain", "tech"] = "main"


class HttpxProbeTool(BaseTool):
    """探活 + Title + 状态码（httpx CLI 优先，缺失降级 builtin）。"""

    name = "httpx_probe"
    description = "单次只读 GET 探活：状态码/标题/跳转（被动 L0）"
    risk_level = "低"
    min_level = 0
    params_model = HttpxParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        """httpx 可用走 CLI（一次进程、单请求）；否则降级 builtin 指纹。"""
        assert isinstance(params, HttpxParams)
        httpx = find_tool("httpx")
        if not httpx:
            from tools.builtin.fingerprint import FingerprintTool

            result = await FingerprintTool(self._settings).run(
                FingerprintTool.params_model(target=params.target)
            )
            result.name = self.name
            result.degraded = True  # HARD
            result.confidence = min(result.confidence, 0.6)
            result.evidence.append("[降级模式] httpx 不可用 → builtin urllib 指纹（技术栈识别率下降）")
            return result
        args = [httpx, "-u", params.target, "-silent", "-status-code", "-title",
                "-tech-detect", "-no-color", "-timeout", str(self._settings.CONNECT_TIMEOUT)]
        if params.follow_redirects:
            args.append("-follow-redirects")
        ret, out, err = await run_command(args, timeout=60)
        if ret != 0 or not out.strip():
            return ToolResult.err(self.name, f"httpx 探测失败: {err[:200] or '(无输出)'}（失败不重试）")
        line = out.strip().splitlines()[0]
        return ToolResult(
            name=self.name, success=True, stdout=line[:500],
            data={"raw": line, "target": params.target},
            evidence=[f"httpx CLI: {line[:120]}"],
            confidence=0.9,
        )
