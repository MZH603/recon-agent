"""JS 资产清单插件：script src 库名与版本提取（对标 Wappalyzer 的资产分析）。"""
from __future__ import annotations

import re

from tools.builtin.signatures import SCRIPT_LIB_NAMES, SCRIPT_VERSION_RE
from tools.techniques.base import Finding, Technique, register


@register
class JsInventoryTechnique(Technique):
    """从首页响应中提取 JS 库及精确版本（如 jquery-3.6.0）。"""

    name = "js_inventory"
    paths = ("/",)

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for body in responses.values():
            for match in SCRIPT_VERSION_RE.finditer(body):
                lib = SCRIPT_LIB_NAMES.get(match.group(1).lower())
                if lib:
                    findings.append(Finding(
                        "js库", lib, 0.9, "[来源: 页面 script 版本]",
                        version=match.group(2)))
        return findings
