"""builtin L3 API 文档发现：swagger/knife4j/druid/actuator 未授权面（只读）。

HARD：固定探测清单 ≤10 路径（禁止字典爆破）；OpenAPI JSON 解析仅提取路径清单；
druid/actuator 未授权命中 = High；扰动控制器熔断即停。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from tools.base import BaseTool, ToolResult
from tools.builtin.fingerprint import split_target
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

# (路径, 判定函数标记)  固定清单（HARD：不加字典、不扩枚举）
DOC_PATHS: tuple[tuple[str, str], ...] = (
    ("/v2/api-docs", "openapi"),
    ("/v3/api-docs", "openapi"),
    ("/api-docs", "openapi"),
    ("/swagger-ui.html", "swagger_ui"),
    ("/swagger-ui/index.html", "swagger_ui"),
    ("/doc.html", "knife4j"),
    ("/knife4j/doc.html", "knife4j"),
    ("/druid/index.html", "druid"),
    ("/actuator", "actuator"),
    ("/actuator/mappings", "actuator"),
)


def extract_openapi_paths(body: str, limit: int = 100) -> dict:
    """纯函数：OpenAPI/Swagger JSON → {endpoint_count, methods, sample}。"""
    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        return {}
    paths = raw.get("paths") or {}
    endpoints: list[str] = []
    for path, ops in list(paths.items())[:limit]:
        if isinstance(ops, dict):
            for method in ops:
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    endpoints.append(f"{method.upper()} {path}")
        else:
            endpoints.append(path)
    return {"endpoint_count": len(paths), "endpoints": endpoints[:60],
            "title": (raw.get("info") or {}).get("title", "")}


def classify_doc(path: str, kind: str, status: int, body: str) -> dict | None:
    """纯函数：文档响应 → 发现分级（未授权=High/需认证=Medium/无=无）。"""
    text = (body or "")[:6000]
    if status == 200:
        if kind == "druid" and ("Druid Stat" in text or "druid" in text.lower()):
            return {"path": path, "kind": kind, "severity": "High",
                    "note": "Druid 监控面可访问（疑似未授权）"}
        if kind == "actuator" and ("_links" in text or "actuator" in text.lower()):
            return {"path": path, "kind": kind, "severity": "High",
                    "note": "Actuator 端点内容暴露"}
        if kind == "openapi":
            parsed = extract_openapi_paths(text)
            if parsed:
                return {"path": path, "kind": kind, "severity": "High",
                        "note": f"OpenAPI 文档未授权（{parsed.get('endpoint_count', 0)} 端点）",
                        "endpoints": parsed.get("endpoints", []),
                        "title": parsed.get("title", "")}
            return {"path": path, "kind": kind, "severity": "Medium",
                    "note": "200 但非 OpenAPI 结构（需人工核实）"}
        if kind in ("swagger_ui", "knife4j") and ("swagger" in text.lower() or "knife4j" in text.lower()):
            return {"path": path, "kind": kind, "severity": "High",
                    "note": "API 文档 UI 未授权可访问"}
    if status in (401, 403):
        return {"path": path, "kind": kind, "severity": "Medium",
                "note": f"文档存在但需认证（HTTP {status}）"}
    return None


class ApiDocProbeParams(BaseModel):
    """API 文档探测参数（单主机）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机或 host:port")


class ApiDocProbeTool(BaseTool):
    """L3 API 文档发现（固定清单 ≤10 路径，只读 GET）。"""

    name = "api_doc_probe"
    description = "swagger/knife4j/druid/actuator 未授权面发现（固定 10 路径，OpenAPI 解析，L3）"
    risk_level = "高"
    min_level = 3
    params_model = ApiDocProbeParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._disturb: DisturbanceController | None = None

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, ApiDocProbeParams)
        host, port, _ = split_target(params.target)
        netloc = f"{host}:{port}" if port else host
        self._disturb = DisturbanceController(host, self._settings)

        scheme = await self._pick_scheme(netloc)
        if scheme is None:
            return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")

        findings: list[dict] = []
        notes: list[str] = []
        try:
            for path, kind in DOC_PATHS:
                status, body = await self._get(scheme, netloc, path)
                if status == -1:
                    continue
                entry = classify_doc(path, kind, status, body)
                if entry:
                    findings.append(entry)
        except DisturbanceSuspendedError as exc:
            notes.append(f"[扰动熔断] {exc}")

        high = sum(1 for f in findings if f.get("severity") == "High")
        data = {"host": netloc, "scheme": scheme, "probed": len(DOC_PATHS),
                "findings": findings, "high_count": high, "notes": notes,
                "disturbance": self._disturb.stats()}
        return ToolResult(
            name=self.name,
            success=True,
            data=data,
            evidence=[f"API 文档探测: {len(DOC_PATHS)} 固定路径，命中 {len(findings)}（High {high}）"]
                     + notes,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.75 if high else (0.55 if findings else 0.4),
        )

    async def _pick_scheme(self, netloc: str) -> str | None:
        for scheme in ("https", "http"):
            status, body = await self._get(scheme, netloc, "/")
            if status != -1:
                return scheme
        return None

    async def _get(self, scheme: str, netloc: str, path: str) -> tuple[int, str]:
        async with self._disturb.slot():
            started = time.monotonic()
            try:
                status, _, body = await run_sync(
                    http_get, f"{scheme}://{netloc}{path}",
                    self._settings.CONNECT_TIMEOUT, False, 100_000)
            except (OSError, ValueError):
                status, body = 0, ""
            self._disturb.observe(status, elapsed_ms=(time.monotonic() - started) * 1000,
                                  body_snippet=body[:200])
        return (status if status else -1), body
