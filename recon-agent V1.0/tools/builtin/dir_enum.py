"""L2 敏感路径枚举 + 信息泄露嗅探（CMS 感知、有界字典、单线程限速、只读 GET）。

发现分级：High=响应体确认敏感内容暴露 / Medium=存在需认证的敏感路径或配置面暴露 /
Info=路径可访问但未见泄露内容。发现全部带证据（响应哈希）进入报告，禁止推测填补。
支持 CMS 感知路径生成（基于指纹阶段识别的 CMS 类型自动注入特有路径）。
"""
from __future__ import annotations

import asyncio
from platforms.sync_worker import run_sync
import hashlib
import urllib.error
import urllib.request

from pydantic import BaseModel, Field, field_validator

from security.stealth import StealthRateLimiter, normalize_host, random_user_agent
from tools.base import BaseTool, ToolResult
from tools.builtin.fingerprint import split_target
from tools.builtin.leak_signatures import (
    DEFAULT_PATHS,
    MAX_PATHS,
    classify_response,
    cms_aware_paths,
)
from utils.config import Settings, get_settings


class DirEnumParams(BaseModel):
    """目录枚举参数：支持 CMS 感知路径生成。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机或 host:port")
    paths: list[str] = Field(default_factory=list, description="自定义路径（与内置字典合并）")
    cms: str = Field("", max_length=32, description="已识别的 CMS 类型（如 drupal/wordpress），用于生成 CMS 特有路径")
    max_paths: int = Field(60, ge=1, le=MAX_PATHS, description="合并后探测路径上限（HARD ≤80，防爆破）")

    @field_validator("paths")
    @classmethod
    def _cap_paths(cls, v: list[str]) -> list[str]:
        if len(v) > MAX_PATHS:
            raise ValueError(f"paths 最多 {MAX_PATHS} 条（HARD：禁止爆破）")
        return v


class DirEnumTool(BaseTool):
    """敏感路径枚举 + 信息泄露嗅探（L2）：只读 GET，发现分级，只记录不利用。"""

    name = "dir_enum"
    description = "敏感路径枚举 + 泄露嗅探（CMS 感知、内容级分析，≤80 条，L2）"
    risk_level = "高"
    min_level = 2
    params_model = DirEnumParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.REQUEST_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """逐路径只读 GET + 内容泄露嗅探；连接失败立即停止（HARD）。"""
        assert isinstance(params, DirEnumParams)
        host, port, _ = split_target(params.target)
        netloc = f"{host}:{port}" if port else host

        # 路径合并：自定义 → CMS 感知 → 内置字典（去重 + 截断）
        merged = list(dict.fromkeys(
            list(params.paths) + list(cms_aware_paths(params.cms)) + list(DEFAULT_PATHS)
        ))[: params.max_paths]

        scheme = await self._pick_scheme(netloc)
        if scheme is None:
            return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")

        found: list[dict] = []
        stopped_early = False
        robots_paths: list[str] = []
        for path in merged:
            async with self._limiter.slot():
                status, body = await run_sync(
                    self._get_response, f"{scheme}://{netloc}{path}")
            if status == -1:  # 连接层失败 → 立即停止（HARD）
                stopped_early = True
                break
            entry = classify_response(path, status, body)
            if entry:
                entry["hash"] = hashlib.sha256(
                    body.encode("utf-8", errors="replace")).hexdigest()[:64]
                found.append(entry)
            # robots.txt 内容 → 提取 Disallow 路径作为额外情报
            if path == "/robots.txt" and status == 200:
                robots_paths = [l.split(":", 1)[1].strip() for l in body.splitlines()
                                if l.strip().lower().startswith("disallow:") and len(l.split(":", 1)) > 1]
                robots_paths = [p for p in robots_paths if p and p != "/"]
                if robots_paths:
                    found.append({"path": "/robots.txt", "status": 200,
                                  "severity": "Info",
                                  "leaks": [{"type": f"robots.txt 泄露 {len(robots_paths)} 条内部路径",
                                             "severity": "Info"}],
                                  "note": f"robots.txt 暴露内部路径: {', '.join(robots_paths[:6])}",
                                  "hash": hashlib.sha256(body.encode()).hexdigest()[:64]})

        found.sort(key=lambda e: {"High": 0, "Medium": 1, "Info": 2}.get(e["severity"], 9))
        high_count = sum(1 for f in found if f["severity"] == "High")
        return ToolResult(
            name=self.name,
            success=True,
            data={"host": netloc, "scheme": scheme, "checked": len(merged),
                  "found": found, "stopped_early": stopped_early,
                  "high_count": high_count, "robots_paths": robots_paths},
            evidence=[f"GET {scheme}://{netloc}{f['path']} -> {f['status']} "
                      f"({f['severity']}: {f['note']})" for f in found] or ["无发现"],
            confidence=0.7,
        )

    async def _pick_scheme(self, netloc: str) -> str | None:
        """首次探测确定可用 scheme（https → http 各一次；-1=连接失败，失败不重试）。"""
        for scheme in ("https", "http"):
            async with self._limiter.slot():
                status, _ = await run_sync(
                    self._get_response, f"{scheme}://{netloc}/")
            if status != -1:
                return scheme
        return None

    def _get_response(self, url: str) -> tuple[int, str]:
        """单次只读 GET：返回 (HTTP 状态码, 响应体前 100KB)；**-1 = 连接层失败**（哨兵）。"""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": random_user_agent()})
            with urllib.request.urlopen(req, timeout=self._settings.CONNECT_TIMEOUT) as resp:
                return resp.status, resp.read(100_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(100_000).decode("utf-8", errors="replace")
            except (OSError, ValueError):
                return exc.code, ""
        except (OSError, ValueError):
            return -1, ""
