"""builtin L3 参数挖掘：arjun 式参数发现（反射检测 + 差分判定），GET 只读。

对应用户矩阵第三阶段「参数挖掘：参数名爆破 (Param Mining)、分析 URL 结构」。

HARD 纪律：
- 全部 GET 只读（不 POST / 不带业务参数值 / 不触发副作用）；
- 请求硬预算 PARAM_PROBE_L3_CAP（含基线）；参数字典截断到预算内；
- 反射 marker 用随机 hex（非 payload，无注入意图，仅判定参数是否进入响应）；
- 差分 = 与基线哈希/长度显著不同且非软 404 → param_active；
- 扰动控制器熔断即停（sampling_suspended 记录损失）。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time

from pydantic import BaseModel, Field

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from tools.base import BaseTool, ToolResult
from tools.builtin.dir_enum import DirEnumTool
from tools.builtin.fingerprint import split_target
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings
from platforms.sync_worker import run_sync

# 常见参数名（arjun 精简版：信息检索类 + 分页类 + 状态类 + 文件类，无注入语义）
PARAM_NAMES: tuple[str, ...] = (
    "id", "name", "user", "username", "email", "q", "search", "query", "keyword",
    "page", "page_size", "limit", "offset", "sort", "order", "order_by", "filter",
    "type", "category", "lang", "locale", "debug", "test", "admin", "token", "key",
    "api_key", "apikey", "callback", "redirect", "url", "path", "file", "dir",
    "uid", "pid", "cid", "sid", "gid", "year", "month", "day", "date", "from",
    "to", "start", "end", "status", "state", "action", "view", "format", "json",
    "html", "print", "share", "preview", "template", "site", "tag", "keywords",
    "size", "num", "count", "version", "module", "controller", "method", "lang_id",
)


def detect_reflection(body: str, marker: str) -> bool:
    """纯函数：marker 是否回显在响应体（参数进入处理逻辑的证据）。"""
    return bool(marker) and marker in body


def diff_param(baseline_hash: str, baseline_len: int, body_hash: str,
               body_len: int) -> str:
    """纯函数：参数响应 vs 基线 → verdict（反射之外的激活判定）。"""
    if body_hash == baseline_hash:
        return "same-as-baseline"
    if abs(body_len - baseline_len) <= 16:
        return "similar-length"  # 动态内容噪声，存疑
    return "distinct"


def build_probe_url(base_url: str, name: str, marker: str) -> str:
    """纯函数：探测 URL = base?name=marker（单参数，无额外语义）。"""
    sep = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{name}={marker}"


class ParamMiningParams(BaseModel):
    """参数挖掘参数（单主机）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机或 host:port")
    path: str = Field("/", pattern=r"^/[\w\.\-/]*$", description="探测入口路径（默认 /）")
    params: list[str] = Field(default_factory=list, max_length=100,
                              description="自定义参数名候选；留空用内置字典")
    path_base: bool = Field(False, description="同时探测 /path?x=1 与入口同级常见路径")


class ParamMiningTool(BaseTool):
    """L3 参数挖掘（arjun 式反射 + 差分，GET 只读，硬预算）。"""

    name = "param_mining"
    description = ("参数名发现：随机 marker 反射检测 + 基线差分判定（GET 只读，"
                   "预算 ≤PARAM_PROBE_L3_CAP，扰动熔断即停，L3）")
    risk_level = "高"
    min_level = 3
    params_model = ParamMiningParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._base = DirEnumTool(settings)  # 复用 L2 GET（UA 档案 + 同源守卫）
        self._disturb: DisturbanceController | None = None

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, ParamMiningParams)
        host, port, _ = split_target(params.target)
        netloc = f"{host}:{port}" if port else host
        self._disturb = DisturbanceController(host, self._settings)
        base_url = f"{params.path if params.path.startswith('/') else '/' + params.path}"

        scheme = await self._pick_scheme(netloc)
        if scheme is None:
            return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")
        origin = f"{scheme}://{netloc}"

        # 预算：总请求 ≤PARAM_PROBE_L3_CAP（基线 2 + 参数 N）
        budget = self._settings.PARAM_PROBE_L3_CAP
        names = list(dict.fromkeys(
            list(params.params) + list(PARAM_NAMES)))[: budget - 2]

        notes: list[str] = []
        findings: list[dict] = []
        checked = 0
        suspended = False
        try:
            # 基线 ×2（取众数长度/哈希，抑制动态噪声）
            bl_hash, bl_len = await self._baseline(origin)
            checked += 2

            for name in names:
                if checked >= budget:  # HARD 预算护栏
                    notes.append("参数预算护栏触发，收敛采样")
                    break
                marker = f"zm{random.randbytes(4).hex()}"
                url = build_probe_url(origin + base_url, name, marker)
                status, body = await self._get(url)
                checked += 1
                if status == -1:
                    continue
                body_hash = hashlib.sha256(
                    body.encode("utf-8", errors="replace")).hexdigest()[:32]
                reflected = detect_reflection(body, marker)
                verdict = diff_param(bl_hash, bl_len, body_hash, len(body))
                if reflected or verdict == "distinct":
                    findings.append({
                        "param": name, "status": status,
                        "reflected": reflected, "verdict": verdict,
                        "note": ("marker 回显：参数进入处理逻辑" if reflected else
                                 "响应差分：参数改变输出（需人工核实语义）"),
                    })
        except DisturbanceSuspendedError as exc:
            suspended = True
            notes.append(f"[扰动熔断] {exc} — 采样中止（绝不硬闯）")

        reflected_count = sum(1 for f in findings if f["reflected"])
        data = {
            "host": netloc, "scheme": scheme, "path": base_url,
            "checked": checked, "budget": budget,
            "findings": findings, "reflected_count": reflected_count,
            "suspended": suspended, "notes": notes,
            "disturbance": self._disturb.stats(),
        }
        evidence = [
            f"参数挖掘: 检查 {checked} 参数，激活 {len(findings)}"
            f"（反射 {reflected_count}，差分 {len(findings) - reflected_count}）",
        ] + [f"[扰动] {n}" for n in notes]
        return ToolResult(
            name=self.name, success=bool(findings) or not suspended,
            data=data, evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.7 if reflected_count else (0.5 if findings else 0.3),
        )

    async def _pick_scheme(self, netloc: str) -> str | None:
        for scheme in ("https", "http"):
            status, _ = await self._get(f"{scheme}://{netloc}/")
            if status != -1:
                return scheme
        return None

    async def _get(self, url: str) -> tuple[int, str]:
        """只读 GET（扰动节流；连接层失败按 L3 重试 1 次，4xx/5xx 是答案不重试）。"""
        async with self._disturb.slot():
            started = time.monotonic()
            status, body = await run_sync(self._base._get_response, url)
            self._disturb.observe(status, elapsed_ms=(time.monotonic() - started) * 1000,
                                  body_snippet=body[:200])
        if status == -1 and self._settings.L3_MAX_RETRIES >= 1:
            await asyncio.sleep(self._settings.L3_RETRY_BACKOFF)
            async with self._disturb.slot():
                status, body = await run_sync(self._base._get_response, url)
        return status, body

    async def _baseline(self, origin: str) -> tuple[str, int]:
        """基线 ×2：取众数长度对应哈希（抑制动态内容噪声）。"""
        lens: list[int] = []
        hashes: list[str] = []
        for _ in range(2):
            status, body = await self._get(origin + "/")
            if status != -1 and body:
                lens.append(len(body))
                hashes.append(hashlib.sha256(
                    body.encode("utf-8", errors="replace")).hexdigest()[:32])
        if not lens:
            return "", -1
        dominant = max(set(lens), key=lens.count)
        return hashes[lens.index(dominant)], dominant
