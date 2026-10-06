"""增量更新（HARD：与上次同目标同工具结果无实质差异 → 仅标 unchanged，不重复进入上下文）。"""
from __future__ import annotations

import hashlib


class IncrementalReporter:
    """记录 (目标, 工具) → 结果摘要哈希；再次采集时比对是否变化。"""

    def __init__(self) -> None:
        self._digests: dict[str, str] = {}

    @staticmethod
    def _key(target: str, tool: str) -> str:
        return f"{target}::{tool}"

    @staticmethod
    def digest(stdout: str) -> str:
        """结果内容摘要。"""
        return hashlib.sha256((stdout or "").encode("utf-8")).hexdigest()[:32]

    def is_unchanged(self, target: str, tool: str, stdout: str) -> bool:
        """与上次结果一致返回 True（调用方应仅标注 unchanged）。"""
        key = self._key(target, tool)
        return self._digests.get(key) == self.digest(stdout)

    def remember(self, target: str, tool: str, stdout: str) -> None:
        """记录本次结果摘要。"""
        self._digests[self._key(target, tool)] = self.digest(stdout)
