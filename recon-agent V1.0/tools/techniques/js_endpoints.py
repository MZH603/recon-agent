"""JS 端点与凭据提取插件（两阶段：Phase 1 发现 JS 路径 → Phase 2 抓取分析）。

从首页提取 `<script src>` JS 路径（follow_up_paths）→ 引擎抓取 JS 文件 →
analyze 阶段从 JS 内容中提取 API 路由 / 硬编码凭据 / 内部 URL / 配置对象。
"""
from __future__ import annotations

import re

from tools.techniques.base import Finding, Technique, register

# Phase 1：从首页 HTML 提取 <script src> 路径
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)

# Phase 2：JS 内容分析签名
API_ROUTE_RE = re.compile(r'["\'](/api/[\w\.\-/]{3,60})["\']')
INTERNAL_URL_RE = re.compile(r'["\'](https?://(?:internal|staging|dev|test|uat)[^"\']{3,80})["\']', re.I)
SECRET_RE = re.compile(
    r'["\'](?:token|secret|api_key|apikey|password|passwd|credential)["\']'
    r'\s*[:=]\s*["\']([A-Za-z0-9_/+\-=]{8,64})["\']', re.I)
CONFIG_KEY_RE = re.compile(
    r'(?:var|let|const)\s+(\w+(?:[A-Z]\w+)*(?:Config|Settings|Options|Env))\s*=',)


@register
class JsEndpointsTechnique(Technique):
    """JS 文件端点与凭据提取（L2）：两阶段探测，需要引擎支持跟进抓取。"""

    name = "js_endpoints"
    paths = ("/",)  # Phase 1：首页（用于提取 JS src URL）

    def __init__(self) -> None:
        self._js_urls: list[str] = []

    def follow_up_paths(self, responses: dict[str, str]) -> tuple[str, ...]:
        """Phase 2 路径发现：从首页 HTML 提取 <script src> JS 路径（≤5 个）。"""
        body = self._homepage_body(responses)
        if not body:
            return ()
        srcs = SCRIPT_SRC_RE.findall(body)
        # 去重、仅保留相对路径（绝对 URL 可能是 CDN/外域）
        js_paths = tuple(dict.fromkeys(
            src for src in srcs if src.startswith("/") and src.endswith(".js")
            or (".js?" in src)
        ))[:5]  # HARD: 跟进抓取 ≤5 个 JS 文件
        self._js_urls = list(js_paths)
        return js_paths

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        """Phase 3：分析 JS 文件内容 → API 路由 / 硬编码凭据 / 内部 URL。"""
        findings: list[Finding] = []
        for js_path in self._js_urls:
            js_body = ""
            for url, body in responses.items():
                if url.endswith(js_path.split("?")[0]) or js_path.split("?")[0] in url:
                    js_body = body
                    break
            if not js_body:
                continue

            # API 路由提取
            api_routes = sorted(set(API_ROUTE_RE.findall(js_body)))[:15]
            if api_routes:
                findings.append(Finding(
                    "情报", f"API 路由 ({len(api_routes)} 条)", 0.8,
                    f"[来源: {js_path}]", version=", ".join(api_routes[:6])))

            # 硬编码凭据
            secrets = SECRET_RE.findall(js_body)
            if secrets:
                findings.append(Finding(
                    "High", "JS 硬编码凭据", 0.9,
                    f"[来源: {js_path}] 值前缀: {secrets[0][:8]}…"))

            # 内部/测试 URL
            internal_urls = sorted(set(INTERNAL_URL_RE.findall(js_body)))[:5]
            if internal_urls:
                findings.append(Finding(
                    "Medium", "JS 内部/测试环境 URL", 0.8,
                    f"[来源: {js_path}]", version=", ".join(internal_urls[:3])))

            # 配置对象
            configs = CONFIG_KEY_RE.findall(js_body)
            if configs:
                findings.append(Finding(
                    "Low", f"JS 配置对象 ({len(configs)})", 0.6,
                    f"[来源: {js_path}] 对象: {', '.join(configs[:5])}"))

        return findings

    @staticmethod
    def _homepage_body(responses: dict[str, str]) -> str:
        """从响应池中取首页 body。"""
        for path, body in responses.items():
            if path.rstrip("/") == "":
                return body
        return ""
