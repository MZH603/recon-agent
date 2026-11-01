"""builtin L3 目录枚举深度版：软 404 基线差分 / 403 绕过头变换 / 一级递归。

HARD：路径上限 DIR_PATHS_L3_CAP（300）；403 绕过每路径 ≤2 变体（全部只读 GET）；
扰动控制器熔断 → 转入 sampling_suspended 记录损失，绝不硬闯；
连接层失败按 L3_MAX_RETRIES 重试 1 次（退避 ≥L3_RETRY_BACKOFF），4xx/5xx 是答案不重试。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from tools.base import BaseTool, ToolResult
from tools.builtin.dir_enum import DirEnumTool
from tools.builtin.fingerprint import split_target
from tools.builtin.leak_signatures import DEFAULT_PATHS, classify_response
from utils.config import Settings, get_settings

# 一级递归：已发现目录 × 常见文件名（有界）
RECURSE_SUFFIXES: tuple[str, ...] = (
    ".bak", ".zip", ".sql", ".old", ".txt", ".env", ".json", ".log",
    "/index.php.bak", "/index.html.bak", "/admin", "/login", "/backup",
    "/web.config", "/.git/HEAD", "/composer.json", "/package.json",
)
RECURSE_DIRS_LIMIT = 3  # HARD: 最多递归 3 个目录
BYPASS_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Original-URL", "{path}"),  # 运行时替换
)


def is_soft404(baseline_hash: str, baseline_len: int, body_hash: str,
               body_len: int) -> bool:
    """纯函数：与不存在路径基线同哈希或近似同长 → catch-all/软404（剔除假阳性）。"""
    if body_hash == baseline_hash:
        return True
    return abs(body_len - baseline_len) <= 16


def build_bypass_variants(path: str) -> list[dict[str, str]]:
    """纯函数：403 路径 → 绕过头变体（≤2，全部只读）。"""
    return [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": path},
    ][:2]


class DirEnumDeepParams(BaseModel):
    """L3 深度目录枚举参数。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机或 host:port")
    paths: list[str] = Field(default_factory=list, max_length=300,
                             description="自定义路径（与内置字典合并）")
    max_paths: int = Field(300, ge=1, le=300, description="HARD ≤DIR_PATHS_L3_CAP")
    bypass_403: bool = Field(True, description="403 路径做 ≤2 种绕过头变换（只读）")
    recurse: bool = Field(True, description="发现目录做一级递归（≤3 目录）")


class DirEnumDeepTool(BaseTool):
    """L3 目录枚举深度版（软 404 基线 + 403 绕过 + 递归 + 扰动熔断）。"""

    name = "dir_enum_deep"
    description = ("L3 深度路径枚举：软 404 基线差分 / 403 绕过头（≤2 变体）/ 一级递归 / "
                   "熔断即停（≤300 条，全部只读）")
    risk_level = "高"
    min_level = 3
    params_model = DirEnumDeepParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._base = DirEnumTool(settings)  # 复用 L2 的 GET 实现与泄露嗅探
        self._disturb: DisturbanceController | None = None

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, DirEnumDeepParams)
        host, port, _ = split_target(params.target)
        netloc = f"{host}:{port}" if port else host
        self._disturb = DisturbanceController(host, self._settings)

        merged = list(dict.fromkeys(
            list(params.paths) + list(DEFAULT_PATHS)))[: params.max_paths]
        scheme = await self._pick_scheme(netloc)
        if scheme is None:
            return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")

        notes: list[str] = []
        suspended = False
        # 软 404 基线：随机不存在路径 ×2
        baseline = await self._baseline(scheme, netloc)
        bl_hash, bl_len = baseline

        found: list[dict] = []
        bypass_hits: list[dict] = []
        checked = 0
        dirs_found: list[str] = []
        try:
            for path in merged:
                if checked >= self._settings.L3_MAX_REQUESTS_PER_HOST + 40:  # HARD 预算护栏
                    notes.append("单主机请求预算护栏触发，收敛采样")
                    break
                status, body = await self._get(scheme, netloc, path)
                checked += 1
                if status == -1:
                    continue  # 连接层失败（已含 1 次重试），跳过该路径
                body_hash = hashlib.sha256(
                    body.encode("utf-8", errors="replace")).hexdigest()[:32]
                if status in (200, 301, 302) and is_soft404(bl_hash, bl_len, body_hash, len(body)):
                    continue  # catch-all/软404，不算发现
                entry = classify_response(path, status, body)
                if entry:
                    entry["hash"] = body_hash
                    found.append(entry)
                    if entry.get("path", "").endswith("/") and status in (200, 301, 302):
                        dirs_found.append(path)
                if status == 403 and params.bypass_403:
                    bypass_hits += await self._try_bypass(scheme, netloc, path)
        except DisturbanceSuspendedError as exc:
            suspended = True
            notes.append(f"[扰动熔断] {exc} — 采样中止，剩余路径放弃（绝不硬闯）")

        # 一级递归（有界）
        if params.recurse and dirs_found and not suspended:
            try:
                for directory in dirs_found[:RECURSE_DIRS_LIMIT]:
                    for suffix in RECURSE_SUFFIXES:
                        if checked >= params.max_paths:  # HARD: 总路径预算
                            break
                        status, body = await self._get(scheme, netloc, directory.rstrip("/") + suffix)
                        checked += 1
                        if status == -1:
                            continue
                        body_hash = hashlib.sha256(
                            body.encode("utf-8", errors="replace")).hexdigest()[:32]
                        if is_soft404(bl_hash, bl_len, body_hash, len(body)):
                            continue
                        entry = classify_response(directory.rstrip("/") + suffix, status, body)
                        if entry:
                            entry["hash"] = body_hash
                            found.append(entry)
            except DisturbanceSuspendedError as exc:
                notes.append(f"[扰动熔断] {exc}")

        found.sort(key=lambda e: {"High": 0, "Medium": 1, "Info": 2}.get(e["severity"], 9))
        high_count = sum(1 for f in found if f["severity"] == "High")
        data = {
            "host": netloc, "scheme": scheme, "checked": checked,
            "baseline": {"length": bl_len, "hash": bl_hash},
            "found": found, "bypass_403_hits": bypass_hits,
            "high_count": high_count, "suspended": suspended, "notes": notes,
            "disturbance": self._disturb.stats(),
        }
        evidence = ([f"软404 基线: {bl_len}B/{bl_hash[:12]}；检查 {checked} 路径，发现 {len(found)}，"
                     f"403 绕过命中 {len(bypass_hits)}"]
                    + [f"[扰动] {n}" for n in notes])
        return ToolResult(
            name=self.name,
            success=bool(found) or not suspended,
            data=data,
            evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.7,
        )

    # ---------- 基础设施（复用 L2 GET + 扰动节流 + 连接层重试 1 次） ----------
    async def _pick_scheme(self, netloc: str) -> str | None:
        for scheme in ("https", "http"):
            status, _ = await self._get(scheme, netloc, "/")
            if status != -1:
                return scheme
        return None

    async def _get(self, scheme: str, netloc: str, path: str) -> tuple[int, str]:
        """只读 GET（扰动节流 + 连接层失败重试 1 次，退避 ≥L3_RETRY_BACKOFF）。"""
        async with self._disturb.slot():
            started = time.monotonic()
            status, body = await run_sync(self._base._get_response,
                                          f"{scheme}://{netloc}{path}")
            self._disturb.observe(status, elapsed_ms=(time.monotonic() - started) * 1000,
                                  body_snippet=body[:200])
        if status == -1 and self._settings.L3_MAX_RETRIES >= 1:  # 仅连接层失败重试
            await asyncio.sleep(self._settings.L3_RETRY_BACKOFF)
            async with self._disturb.slot():
                status, body = await run_sync(self._base._get_response,
                                              f"{scheme}://{netloc}{path}")
        return status, body

    async def _baseline(self, scheme: str, netloc: str) -> tuple[str, int]:
        """软 404 基线：2 条随机路径取众数长度与哈希。"""
        lens: list[int] = []
        hashes: list[str] = []
        for _ in range(2):
            path = f"/{self._rnd()}"
            status, body = await self._get(scheme, netloc, path)
            if status not in (-1,) and body:
                lens.append(len(body))
                hashes.append(hashlib.sha256(
                    body.encode("utf-8", errors="replace")).hexdigest()[:32])
        if not lens:
            return "", -1
        dominant = max(set(lens), key=lens.count)
        idx = lens.index(dominant)
        return hashes[idx], dominant

    async def _try_bypass(self, scheme: str, netloc: str, path: str) -> list[dict]:
        """403 路径 ≤2 种绕过头变换（只读；命中=绕过成功线索）。"""
        hits: list[dict] = []
        for extra in build_bypass_variants(path):
            headers = {k: (v.replace("{path}", path)) for k, v in extra.items()}
            async with self._disturb.slot():
                try:
                    status, body = await run_sync(
                        self._base._get_response_with_headers,
                        f"{scheme}://{netloc}{path}", headers)
                except (OSError, ValueError):
                    status, body = -1, ""
            if status == 200:
                hits.append({"path": path, "via": headers, "status": status,
                             "note": "403 绕过命中（需人工核实真实放行）"})
        return hits

    @staticmethod
    def _rnd() -> str:
        return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))
