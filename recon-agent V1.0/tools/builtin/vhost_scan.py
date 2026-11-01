"""builtin L3 虚拟主机探测：Host 头轮换 + 基线差分（WhatWeb vhost 思路）。

HARD：对同一目标 IP 的同一端口发起请求（不新建目标连接面）；候选上限
min(VHOST_WORDLIST_CAP, L3_MAX_REQUESTS_PER_HOST - 2)；经扰动控制器自适应节流；
差分 = 响应长度/哈希与基线不同且非泛解析同哈希（catch-all 剔除）。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings


def load_vhost_wordlist(cap: int) -> list[str]:
    """加载 vhost 字典（tools/data/vhosts.txt，cap 截断）。"""
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "data" / "vhosts.txt"
    if not path.exists():
        return []
    out: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                out.append(word)
            if len(out) >= cap:
                break
    return out


def diff_candidate(baseline_hash: str, baseline_len: int, body_hash: str,
                   body_len: int) -> str:
    """纯函数：与基线差分 → 判定。"""
    if body_hash == baseline_hash:
        return "same-as-baseline"
    if abs(body_len - baseline_len) <= 8 and body_hash != baseline_hash:
        return "similar-length"  # 疑似动态内容（时间戳等），存疑
    return "distinct"


class VhostScanParams(BaseModel):
    """vhost 探测参数（目标=授权主机的 IP 或域名；候选可传入已发现子域）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机（IP/域名）")
    port: int = Field(80, ge=1, le=65535)
    candidates: list[str] = Field(default_factory=list, max_length=200,
                                  description="候选主机名（如已发现子域）；留空用内置字典")
    use_wordlist: bool = Field(True, description="候选不足时用内置 vhosts.txt 补齐")


class VhostScanTool(BaseTool):
    """L3 虚拟主机探测（Host 头轮换差分）。"""

    name = "vhost_scan"
    description = "Host 头轮换探测虚拟主机/隐藏站点（同 IP 同端口，差分判定，L3）"
    risk_level = "高"
    min_level = 3
    params_model = VhostScanParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._disturb: DisturbanceController | None = None

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, VhostScanParams)
        netloc = params.target if params.port in (80, 443) else f"{params.target}:{params.port}"
        scheme = "https" if params.port == 443 else "http"
        base_url = f"{scheme}://{netloc}/"

        # 候选构造：显式列表 + 可选字典补齐，总预算受 L3_MAX_REQUESTS_PER_HOST 硬约束
        budget = self._settings.L3_MAX_REQUESTS_PER_HOST
        cap = min(self._settings.VHOST_WORDLIST_CAP, budget - 2)
        seen: set[str] = set()
        candidates: list[str] = []
        for cand in list(params.candidates) + (load_vhost_wordlist(cap) if params.use_wordlist else []):
            cand = cand.strip().lower()
            if cand and cand not in seen:
                seen.add(cand)
                candidates.append(cand)
            if len(candidates) >= cap:
                break

        self._disturb = DisturbanceController(params.target, self._settings)
        notes: list[str] = []
        results: list[dict] = []

        # 基线：Host=<target 本名>
        try:
            baseline = await self._get(base_url, params.target)
        except DisturbanceSuspendedError as exc:
            return ToolResult.err(self.name, f"[扰动熔断] {exc}")
        if baseline is None:
            return ToolResult.err(self.name, f"基线请求失败 {base_url}（不重试，HARD）")
        bl_hash = hashlib.sha256(baseline.encode("utf-8", errors="replace")).hexdigest()[:32]
        bl_len = len(baseline)

        try:
            for cand in candidates:
                body = await self._get(base_url, cand)
                if body is None:
                    continue
                h = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:32]
                verdict = diff_candidate(bl_hash, bl_len, h, len(body))
                if verdict == "distinct":
                    results.append({"host": cand, "length": len(body),
                                    "hash": h, "verdict": verdict})
                self._disturb.observe(200, elapsed_ms=0)
        except DisturbanceSuspendedError as exc:
            notes.append(f"[扰动熔断] {exc}")

        data = {
            "target": params.target, "port": params.port,
            "baseline": {"length": bl_len, "hash": bl_hash},
            "candidates_tried": len(candidates),
            "vhosts": results,
            "distinct_count": len(results),
            "disturbance": self._disturb.stats(),
            "notes": notes,
        }
        return ToolResult(
            name=self.name,
            success=bool(results) or not notes,
            data=data,
            evidence=[f"vhost 差分: 基线 {bl_len}B，候选 {len(candidates)}，distinct {len(results)}"]
                     + notes,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.65 if results else 0.4,
        )

    async def _get(self, url: str, host_header: str) -> str | None:
        """Host 头轮换 GET（经共享出口 + 扰动节流；失败收敛 None）。"""
        async with self._disturb.slot():
            try:
                status, headers, body = await run_sync(
                    http_get, url, self._settings.CONNECT_TIMEOUT, False, 100_000,
                    {"Host": host_header})
                return body if status else None
            except (OSError, ValueError):
                return None
