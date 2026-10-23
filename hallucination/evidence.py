"""证据绑定（HARD：ToolResult 必须携带 evidence + source_hash；无证据结论强制标注未确认）。"""
from __future__ import annotations

import hashlib

from tools.base import ToolResult

UNCERTAIN_TAG = "[未确认，建议人工核实]"


def bind_evidence(result: ToolResult, source: str, response_body: bytes = b"") -> ToolResult:
    """给 ToolResult 附加上来源 + source_hash（链式可用）。"""
    if source and source not in result.evidence:
        result.evidence.append(source)
    if response_body:
        result.source_hash = hashlib.sha256(response_body).hexdigest()[:64]
    return result


def assert_grounded(finding: str, evidence: list[str]) -> str:
    """无证据结论 → 强制降级为 [未确认，建议人工核实]（HARD：不编造）。"""
    if not evidence:
        return f"{finding} {UNCERTAIN_TAG}"
    return finding


class EvidenceStore:
    """任务级证据登记簿：报告一致性校验的数据源。"""

    def __init__(self) -> None:
        self._items: list[dict] = []

    def add(self, result: ToolResult) -> str:
        """登记一条工具结果，返回证据 ID（E{n}）。"""
        eid = f"E{len(self._items) + 1}"
        self._items.append({
            "id": eid,
            "tool": result.name,
            "success": result.success,
            "evidence": list(result.evidence),
            "source_hash": result.source_hash,
            "confidence": result.confidence,
            "degraded": result.degraded,
        })
        return eid

    def all(self) -> list[dict]:
        """全部证据条目。"""
        return list(self._items)

    def has_source(self, source: str) -> bool:
        """判断某来源是否已登记（一致性校验用）。"""
        return any(source in item["evidence"] for item in self._items)
