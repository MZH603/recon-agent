"""WhatWeb 式探测插件基类与注册表（支持两阶段探测：初始→跟进→分析）。

新增探测技术 = 写一个 Technique 子类并用 @register 注册，引擎自动：
Phase 1 抓取插件声明的初始路径 → Phase 2 抓取插件从初始响应中发现的跟进路径
→ Phase 3 调用 analyze(全部响应) 产出 Findings。

无需改动 deep_fingerprint 引擎代码。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    """单条指纹发现（与 fingerprint._add 语义对齐）。"""

    category: str
    name: str
    confidence: float
    source: str
    version: str = ""


class Technique:
    """探测插件基类。

    - paths: 需要抓取的初始路径（Phase 1，引擎统一限速抓取）；
    - follow_up_paths(responses): 从初始响应中发现的跟进路径（Phase 2，可选）；
    - analyze(responses): 按全部响应到响应体的映射产出 Finding 列表（Phase 3）。
    """

    name: str = ""
    paths: tuple[str, ...] = ()

    def follow_up_paths(self, responses: dict[str, str]) -> tuple[str, ...]:
        """从 Phase 1 响应中发现需要额外抓取的路径（子类可选覆盖）。"""
        return ()

    def analyze(self, responses: dict[str, str]) -> list[Finding]:
        """分析全部响应体（Phase 3，子类必须实现）。"""
        raise NotImplementedError


REGISTRY: list[Technique] = []


def register(cls):
    """插件注册装饰器（引擎启动时自动发现全部已注册技术）。"""
    REGISTRY.append(cls())
    return cls
