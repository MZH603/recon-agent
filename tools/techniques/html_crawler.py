"""HTML 页面结构分析插件：链接提取 / 表单发现 / 注释泄露 / 邮箱采集 / JS 资产发现。

从首页 HTML 中提取对红队有价值的结构化情报：
- 内部链接路径（后续枚举候选）
- 表单 action 端点（登录/搜索/上传面）
- HTML 注释中的敏感信息（TODO/FIXME/密码/调试标记）
- 邮箱地址（社会工程面）
- `<script src>` JS 路径（供 js_endpoints 插件跟进）
"""
from __future__ import annotations

import re

from tools.techniques.base import Finding, Technique, register

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")
FORM_ACTION_RE = re.compile(r'<form[^>]*action=["\']([^"\']{2,80})["\']', re.I)
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
INTERNAL_LINK_RE = re.compile(r'href=["\'](/[^"\']{2,100})["\']')
SENSITIVE_COMMENT_KW = ("todo", "fixme", "hack", "bug", "password", "key",
                        "debug", "admin", "test", "remove", "deprecated",
                        "config", "secret", "internal", "api")


@register
class HtmlCrawlerTechnique(Technique):
    """HTML 结构分析（单次 GET 首页，纯被动 L0）。"""

    name = "html_crawler"
    paths = ("/",)

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        body = self._homepage(responses)
        if not body:
            return findings

        # 内部链接路径
        links = sorted(set(INTERNAL_LINK_RE.findall(body)))[:30]
        if links:
            findings.append(Finding(
                "情报", f"内部链接 ({len(links)} 条)", 0.9,
                "[来源: HTML href]", version=", ".join(links[:8])))

        # 邮箱地址
        emails = sorted(set(EMAIL_RE.findall(body)))[:10]
        if emails:
            findings.append(Finding(
                "情报", f"邮箱地址 ({len(emails)})", 0.9,
                "[来源: 页面文本]", version=", ".join(emails[:5])))

        # 表单 action 端点
        forms = sorted(set(FORM_ACTION_RE.findall(body)))[:10]
        if forms:
            findings.append(Finding(
                "情报", f"表单端点 ({len(forms)})", 0.8,
                "[来源: HTML form action]", version=", ".join(forms[:5])))

        # 敏感 HTML 注释
        comments = [c.strip()[:80] for c in HTML_COMMENT_RE.findall(body)
                    if any(kw in c.lower() for kw in SENSITIVE_COMMENT_KW)]
        if comments:
            findings.append(Finding(
                "Low", f"敏感 HTML 注释 ({len(comments)} 条)", 0.8,
                "[来源: HTML 注释]", version=comments[0]))

        return findings

    @staticmethod
    def _homepage(responses: dict[str, str]) -> str:
        """从响应池中取首页 body。"""
        for path, body in responses.items():
            if path.rstrip("/") == "" or path.rstrip("/").endswith((".html", ".htm")):
                return body
        return next(iter(responses.values()), "") if responses else ""
