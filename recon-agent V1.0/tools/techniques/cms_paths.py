"""CMS 特征路径插件（登录面/REST 端点，对标 WhatWeb 的 CMS 插件）。"""
from __future__ import annotations

import re

from tools.techniques.base import Finding, Technique, register

# (路径, 响应特征正则, 名称, 置信度)
CMS_PROBES: tuple[tuple[str, str, str, float], ...] = (
    ("/wp-login.php", r"wp-content|wp-admin|user_login", "WordPress", 0.95),
    ("/wp-json/", r'"namespaces"', "WordPress(REST)", 0.95),
    ("/administrator/", r"joomla", "Joomla", 0.9),
    ("/user/login", r"drupal", "Drupal", 0.9),
)


@register
class CmsPathsTechnique(Technique):
    """探测常见 CMS 特征路径（存在即强信号，L2 授权下执行）。"""

    name = "cms_paths"
    paths = tuple(path for path, *_ in CMS_PROBES)

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for path, marker, name, conf in CMS_PROBES:
            body = responses.get(path, "")
            if body and re.search(marker, body, re.I):
                findings.append(Finding("cms", name, conf, f"[来源: 特征路径 {path}]"))
        return findings
