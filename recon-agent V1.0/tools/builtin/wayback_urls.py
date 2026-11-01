"""Wayback Machine 历史端点采集（L0 纯被动：CDX API，只查 archive.org）。"""
from __future__ import annotations

import asyncio
from platforms.sync_worker import run_sync
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
    mine_params: bool = Field(True, description="二次 CDX 查询挖掘带参 URL（ParamSpider 式，+1 请求）")


def extract_params(urls: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """纯函数：带参 URL 列表 → ({路径: [参数名...]}, 去重参数名列表)（ParamSpider 式）。"""
    per_path: dict[str, list[str]] = {}
    all_names: set[str] = set()
    for url in urls:
        if "?" not in url:
            continue
        path, _, qs = url.partition("?")
        try:
            pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True)
        except ValueError:
            continue
        names = sorted({k for k, _ in pairs})
        if not names:
            continue
        bucket = per_path.setdefault(path[:200], [])
        for name in names:
            if name not in bucket:
                bucket.append(name)
        all_names.update(names)
    return per_path, sorted(all_names)


class WaybackTool(BaseTool):
    """历史 URL/端点挖掘：旧接口、下线未删的服务路径 + 历史参数名（对红队常比当前扫描更有价值）。"""

    name = "wayback_urls"
    description = "Wayback CDX 历史端点采集：旧接口/下线路径/历史参数名（纯被动 L0，1-2 次查询）"
    risk_level = "低"
    min_level = 1  # v1.1: L0 已并入 L1（基础侦察）
    params_model = WaybackParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.L0_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """CDX 查询（archive.org），失败显式记录不重试；参数挖掘 +1 请求。"""
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
                raw = await run_sync(self._get, api)
            except (OSError, ValueError) as exc:
                return ToolResult.err(self.name, f"web.archive.org 不可达: {type(exc).__name__}（不重试）")
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            return ToolResult.err(self.name, f"CDX 输出解析失败: {exc}")
        urls = [r[0] for r in rows if isinstance(r, list) and r and r[0] != "original"]
        paths = sorted({u.split("?", 1)[0].split(domain, 1)[-1] for u in urls})[:30]

        param_urls: dict[str, list[str]] = {}
        param_names: list[str] = []
        notes: list[str] = []
        if params.mine_params:
            param_api = (
                "https://web.archive.org/cdx/search/cdx?"
                + urllib.parse.urlencode({
                    "url": f"*.{domain}/*", "output": "json", "fl": "original",
                    "collapse": "urlkey", "limit": params.limit,
                    "filter": "original:.*\\?.*",
                })
            )
            async with self._limiter.slot():
                try:
                    raw2 = await run_sync(self._get, param_api)
                    rows2 = json.loads(raw2)
                    urls2 = [r[0] for r in rows2 if isinstance(r, list) and r and r[0] != "original"]
                    param_urls, param_names = extract_params(urls2)
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    notes.append(f"参数挖掘查询失败（不重试，HARD）: {type(exc).__name__}")

        data = {
            "domain": domain, "count": len(urls), "urls": urls[:50], "paths": paths,
            "params": dict(list(param_urls.items())[:30]),
            "param_names": param_names[:60],
        }
        evidence = [
            f"web.archive.org CDX: {len(urls)} 条历史 URL（filter=200）",
            f"历史参数名 {len(param_names)} 个（{len(param_urls)} 条带参路径）",
        ] + notes
        return ToolResult(
            name=self.name,
            success=True,
            data=data,
            evidence=evidence,
            source_hash=hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64],
            confidence=0.7,
        )

    def _get(self, url: str) -> str:
        _, _, body = http_get(url, self._settings.CONNECT_TIMEOUT * 3, max_bytes=2_000_000)
        return body
