"""favicon 关联插件：md5 哈希 → 跨主机同值 = 同源 CMS 部署（Wappalyzer 式思路）。"""
from __future__ import annotations

import hashlib

from tools.techniques.base import Finding, Technique, register


@register
class FaviconTechnique(Technique):
    """抓取 /favicon.ico 计算 md5；无内置哈希库时作为跨主机关联锚点。"""

    name = "favicon"
    paths = ("/favicon.ico",)

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for body in responses.values():
            if body:
                digest = hashlib.md5(body.encode("latin-1", errors="ignore"), usedforsecurity=False).hexdigest()
                findings.append(Finding(
                    "情报", "favicon", 1.0,
                    "[来源: favicon 关联]（跨主机同值 = 同源部署）", version=digest))
        return findings
