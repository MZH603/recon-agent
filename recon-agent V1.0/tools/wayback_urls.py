"""Wayback Machine 历史端点采集（L0 纯被动：CDX API，只查 archive.org）。"""
from __future__ import annotations

import asyncio
import hashlib
import json
import urllib.parse

from pydantic import BaseModel, Field

from security.stealth import StealthRateLimiter, normalize_host
from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings


class WaybackParams(BaseModel):
    """历史端点采集参数（有界）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$")
    limit: int = Field(100, ge=10, le=500, description="最多拉取的历史 URL 条数")


class WaybackTool(BaseTool):
    """历史 URL/端点挖掘：旧接口、下线未删的服务路径（对红队常比当前扫描更有价值）。"""

    name = "wayback_urls"
    description = "Wayback CDX 历史端点采集：旧接口/下线路径（纯被动 L0，单次查询）"
    risk_level = "低"
    min_level = 0
    params_model = WaybackParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.L0_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """单次 CDX 查询（archive.org），失败显式记录不重试。"""
        assert isinstance(params, WaybackParams)
        domain = normalize_host(params.target)
        api = (
            "https://web.archive.org/cdx/search/cdx?"
            + urllib.parse.urlencode({
                "url": f"*.{domain}/*", "output": "json", "fl": "original",
                "collapse": "urlkey", "limit": params.limit, "filter": "statuscode:200",
            })
        )
        async with self._limiter.slot():
            try:
                raw = await asyncio.to_thread(self._get, api)
            except (OSError, ValueError) as exc:
                return ToolResult.err(self.name, f"web.archive.org 不可达: {type(exc).__name__}（不重试）")
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ToolResult.err(self.name, f"CDX 输出解析失败: {exc}")
        urls = [r[0] for r in rows if isinstance(r, list) and r and r[0] != "original"]
        paths = sorted({u.split("?", 1)[0].split(domain, 1)[-1] for u in urls})[:30]
        return ToolResult(
            name=self.name,
            success=True,
            data={"domain": domain, "count": len(urls), "urls": urls[:50], "paths": paths},
            evidence=[f"web.archive.org CDX: {len(urls)} 条历史 URL（filter=200）"],
            source_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64],
            confidence=0.7,
        )

    def _get(self, url: str) -> str:
        _, _, body = http_get(url, self._settings.CONNECT_TIMEOUT * 3, max_bytes=2_000_000)
        return body
