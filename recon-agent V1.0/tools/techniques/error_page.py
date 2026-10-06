"""错误页指纹插件（对标 WhatWeb 的 404 页检测：默认错误页暴露中间件）。"""
from __future__ import annotations

import random

from tools.techniques.base import Finding, Technique, register

ERROR_SIGNATURES: tuple[tuple[str, str, str, float], ...] = (
    ("Apache Tomcat", "middleware", "Tomcat", 0.95),
    ("whitelabel error page", "framework", "Spring Boot", 0.95),
    ("HTTP Error 404", "server", "IIS", 0.9),
    ("<center>nginx</center>", "server", "Nginx", 0.9),
    ("Error 404--Not Found", "middleware", "WebLogic", 0.95),
    ("WebSphere Application Server", "middleware", "WebSphere", 0.95),
    ("Welcome to nginx", "server", "Nginx", 0.9),
)


def match_error_page(body: str) -> tuple[str, str, float] | None:
    """模块级匹配函数（可复用）：返回 (类别, 名称, 置信度) 或 None。"""
    for marker, category, name, conf in ERROR_SIGNATURES:
        if marker.lower() in body.lower():
            return category, name, conf
    return None


@register
class ErrorPageTechnique(Technique):
    """请求随机不存在路径，用默认错误页特征识别中间件/框架。"""

    name = "error_page"

    def paths(self) -> tuple[str, ...]:
        return (f"/nonexistent-recon-{random.randint(10000, 99999)}",)

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for body in responses.values():
            hit = match_error_page(body)
            if hit:
                findings.append(Finding(hit[0], hit[1], hit[2], "[来源: 错误页指纹]"))
        return findings
