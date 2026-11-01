"""builtin 搜索引擎 Dorking（L0 被动：模板引擎 + 无 Key 后端链）。

后端链（settings.DORK_BACKENDS 顺序，失败换源不重试同源）：
- duckduckgo: html.duckduckgo.com/html/（无 Key）
- baidu:      www.baidu.com/s（无 Key，重定向链接如实记录）
HARD：只记录搜索结果条目（URL+标题），绝不抓取目标页面；
出站请求总预算 DORK_MAX_REQUESTS；模板库 tools/data/dorks.yaml 热加载。
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

# ---- 模板库加载（热加载，仿 fingerprint_loader）----
_dorks_cache: "DorkTemplates | None" = None
_dorks_mtime: float | None = None


class DorkTemplates:
    """dorks.yaml 加载结果（query/intent/severity 三元组列表）。"""

    def __init__(self, dorks: list[dict[str, Any]]):
        self.dorks = tuple(
            (d["query"], d.get("intent", ""), d.get("severity", "Info")) for d in dorks)

    @classmethod
    def load_from_yaml(cls, path: Path) -> "DorkTemplates":
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data.get("dorks", []) or [])

    @classmethod
    def load_default(cls) -> "DorkTemplates":
        default = Path(__file__).resolve().parents[1] / "data" / "dorks.yaml"
        return cls.load_from_yaml(default)


def get_dorks(settings: Settings | None = None, reload: bool = False) -> DorkTemplates:
    """取模板库（TOOL_EVIDENCE_DIR/dorks.yaml 覆盖默认；mtime 热加载）。"""
    global _dorks_cache, _dorks_mtime
    s = settings or get_settings()
    path = Path(s.TOOL_EVIDENCE_DIR) / "dorks.yaml" if s.TOOL_EVIDENCE_DIR else None
    if not path or not path.exists():
        path = Path(__file__).resolve().parents[1] / "data" / "dorks.yaml"
    mtime = path.stat().st_mtime if path.exists() else 0
    if _dorks_cache is None or reload or mtime != _dorks_mtime:
        _dorks_cache = DorkTemplates.load_from_yaml(path)
        _dorks_mtime = mtime
    return _dorks_cache


def render_dorks(domain: str, templates: DorkTemplates) -> list[tuple[str, str, str]]:
    """纯函数：模板 + 域名 → [(query, intent, severity)]。"""
    safe = domain.strip()
    return [(q.format(domain=safe), intent, sev) for q, intent, sev in templates.dorks if safe]


# ---- 后端解析（纯函数，便于离线测试）----
_DDG_LINK_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_BAIDU_LINK_RE = re.compile(r'<h3[^>]*>\s*<a[^>]+href="(http[^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def _clean_title(raw: str) -> str:
    return _TAG_RE.sub("", raw or "").strip()[:200]


def parse_ddg(html: str) -> list[dict]:
    """DuckDuckGo HTML 结果解析（含 //duckduckgo.com/l/?uddg= 重定向还原）。"""
    out: list[dict] = []
    for href, title in _DDG_LINK_RE.findall(html or ""):
        url = href
        if "uddg=" in href:
            try:
                from urllib.parse import parse_qs, urlsplit
                qs = parse_qs(urlsplit("https:" + href if href.startswith("//") else href).query)
                url = (qs.get("uddg") or [""])[0]
            except ValueError:
                url = href
        if url:
            out.append({"title": _clean_title(title), "url": url})
    return out[:15]


def parse_baidu(html: str) -> list[dict]:
    """百度结果解析（link?url= 跳转链接如实记录，注明为跳转地址）。"""
    out: list[dict] = []
    for href, title in _BAIDU_LINK_RE.findall(html or ""):
        out.append({"title": _clean_title(title), "url": href})
    return out[:15]


_BACKEND_PARSERS = {"duckduckgo": parse_ddg, "baidu": parse_baidu}
_BACKEND_URLS = {
    "duckduckgo": "https://html.duckduckgo.com/html/?q=",
    "baidu": "https://www.baidu.com/s?wd=",
}


class DorkSearchParams(BaseModel):
    """Dork 搜索参数（主域名；模板由 YAML 热加载）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="主域名")
    max_hits_per_dork: int = Field(10, ge=1, le=15)


class DorkSearchTool(BaseTool):
    """搜索引擎 Dorking（L0 被动：第三方搜索引擎，不接触目标基础设施）。"""

    name = "dork_search"
    description = "搜索引擎 dorking：site:/filetype:/inurl: 模板库发现被索引敏感文件与后台（被动 L0）"
    risk_level = "低"
    min_level = 1  # v1.1: L0 已并入 L1（基础侦察）
    params_model = DorkSearchParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, DorkSearchParams)
        domain = params.target.lower().rstrip(".")
        dorks = render_dorks(domain, get_dorks(self._settings))
        budget = self._settings.DORK_MAX_REQUESTS  # HARD
        backend_chain = [b for b in self._settings.DORK_BACKENDS if b in _BACKEND_PARSERS]

        results: list[dict] = []
        notes: list[str] = []
        queries_run = 0
        active_backend = backend_chain[0] if backend_chain else ""

        for query, intent, severity in dorks:
            if queries_run >= budget:  # HARD 预算熔断
                notes.append(f"请求预算耗尽（{budget}），剩余 {len(dorks) - queries_run} 条 dork 未执行")
                break
            if not backend_chain:
                notes.append("无可用搜索后端（检查 DORK_BACKENDS 配置）")
                break
            queries_run += 1
            hits: list[dict] = []
            used_backend = ""
            for backend in backend_chain:
                status, _, body = await self._fetch(backend, query)
                if status == 200:
                    hits = _BACKEND_PARSERS[backend](body)
                    if hits:
                        used_backend = backend
                        break
                # 空结果/失败 → 换下一后端（同源不重试，HARD）
            else:
                notes.append(f"全部后端无结果: {query[:50]}")
            results.append({
                "dork": query, "intent": intent, "severity": severity,
                "backend": used_backend or active_backend,
                "hits": hits[: params.max_hits_per_dork],
                "hit_count": len(hits),
            })

        high_count = sum(1 for r in results
                         if r["severity"] == "High" and r["hit_count"] > 0)
        data = {
            "target": domain, "queries_run": queries_run, "budget": budget,
            "backend_chain": backend_chain, "results": results,
            "high_count": high_count, "notes": notes,
        }
        evidence = [
            f"搜索引擎 dorking: {domain}，{queries_run}/{budget} 请求（仅记录结果页条目）",
            "不抓取目标页面（HARD）；命中 URL 需人工判断后再访问",
        ]
        return ToolResult(
            name=self.name,
            success=queries_run > 0,
            data=data,
            evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.6 if results else 0.3,
        )

    async def _fetch(self, backend: str, query: str) -> tuple[int, dict, str]:
        """单次搜索请求（同步经共享出口；失败收敛不抛）。"""
        import asyncio
        from platforms.sync_worker import run_sync

        url = _BACKEND_URLS[backend] + urllib.parse.quote(query)
        try:
            return await run_sync(http_get, url, self._settings.CONNECT_TIMEOUT, False, 300_000)
        except (OSError, ValueError):
            return 0, {}, ""
