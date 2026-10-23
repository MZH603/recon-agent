"""L2 深度指纹引擎（对标 WhatWeb 的插件架构）。

引擎只做三件事：抓取插件声明的路径 → 分发 analyze → 合并 Findings。
新增探测技术 = 在 tools/techniques/ 下注册新插件，引擎零改动。

- 基线卡片：复用 L0 FingerprintTool 的 Header/meta 特征并合并
HARD：min_level=2（三级门控）；单目标探测请求 ≤8 次；单线程限速 3-10s。
"""
from __future__ import annotations

import asyncio
from platforms.sync_worker import run_sync
import hashlib
import json
import urllib.request

from pydantic import BaseModel, Field

from security.stealth import StealthRateLimiter, random_user_agent
from tools.base import BaseTool, ToolResult
from tools.builtin.fingerprint import FingerprintParams, FingerprintTool, _add, split_target
from tools.techniques import REGISTRY  # noqa: F401 —— 导入即注册
from utils.config import Settings, get_settings

PROBE_LIMIT = 8  # HARD: 单目标插件探测请求上限（scheme 协商另计）


class DeepFingerprintParams(BaseModel):
    """深度指纹参数（单主机）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$")
    include_baseline: bool = Field(True, description="先做 L0 被动基线卡片并合并")


class DeepFingerprintTool(BaseTool):
    """深度指纹（L2）：插件式多路径探测，产出合并技术栈卡片。"""

    name = "deep_fingerprint"
    description = "WhatWeb 式深度指纹（插件化）：错误页/CMS 特征路径/favicon/JS 资产（L2）"
    risk_level = "高"
    min_level = 2
    params_model = DeepFingerprintParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.REQUEST_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, DeepFingerprintParams)
        host, port, _ = split_target(params.target)
        netloc = f"{host}:{port}" if port else host
        findings: dict = {}
        evidence: list[str] = []

        if params.include_baseline:
            base = await FingerprintTool(self._settings).run(FingerprintParams(target=params.target))
            if base.success:
                findings.update(base.data.get("tech", {}))
                evidence += [f"[基线] {e}" for e in base.evidence[:3]]

        scheme = await self._pick_scheme(netloc)
        if scheme is None:
            return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")

        responses: dict[str, str] = {}
        probes = 0
        for technique in REGISTRY:
            paths = technique.paths() if callable(technique.paths) else technique.paths
            for path in paths:
                if probes >= PROBE_LIMIT:  # HARD: 请求上限
                    break
                if path not in responses:
                    responses[path] = await self._get(f"{scheme}://{netloc}{path}")
                    probes += 1
            if probes >= PROBE_LIMIT:
                break

        # Phase 2: 跟进路径（JS 文件等，由插件从 Phase 1 响应中发现）
        follow_budget = 5  # HARD: 跟进抓取上限
        for technique in REGISTRY:
            follow = technique.follow_up_paths(responses)
            for path in follow:
                if probes >= PROBE_LIMIT + follow_budget:
                    break
                if path not in responses:
                    responses[path] = await self._get(f"{scheme}://{netloc}{path}")
                    probes += 1

        favicon_md5 = ""
        for technique in REGISTRY:
            for finding in technique.analyze(responses):
                _add(findings, finding.category, finding.name,
                     finding.confidence, finding.source, finding.version)
                if finding.name == "favicon":
                    favicon_md5 = finding.version
        if favicon_md5:
            evidence.append(f"favicon md5: {favicon_md5}（跨主机同值 = 同源部署）")

        confidence = max([f["confidence"] for f in findings.values()], default=0.5)
        card = {"host": netloc, "status": 200, "title": "", "scheme": scheme,
                "confidence": confidence, "tech": findings, "favicon_md5": favicon_md5,
                "robots_hints": [], "sitemap_hints": [], "deep": True,
                "techniques": [t.name for t in REGISTRY]}
        return ToolResult(name=self.name, success=True, data=card, evidence=evidence,
                          source_hash=hashlib.sha256(
                              json.dumps(findings, sort_keys=True).encode()).hexdigest()[:64],
                          confidence=confidence)

    async def _get(self, url: str) -> str:
        """单次只读 GET（带限速）；任何失败返回空串（不重试，HARD）。"""
        async with self._limiter.slot():
            try:
                return await run_sync(self._sync_get, url)
            except (OSError, ValueError):
                return ""

    @staticmethod
    def _sync_get(url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": random_user_agent()})
        with urllib.request.urlopen(req, timeout=get_settings().CONNECT_TIMEOUT) as resp:
            return resp.read(100_000).decode("utf-8", errors="replace")

    async def _pick_scheme(self, netloc: str) -> str | None:
        """https → http 各探测一次（计入探测预算之外）。"""
        for scheme in ("https", "http"):
            if await self._get(f"{scheme}://{netloc}/"):
                return scheme
        return None
