"""CVE 知识库：只读签名快照 + 否定证据（HARD：查不到硬输出"未收录"，禁止编造 CVE 编号）。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, Field

from utils.logger import warn


class CVEKnowledgeBase:
    """本地 CVE 快照检索（防投毒：SHA256 签名校验，不匹配拒绝加载）。"""

    def __init__(self, entries: dict, snapshot_date: str, source: str) -> None:
        self._entries = entries
        self.snapshot_date = snapshot_date
        self.source = source

    @classmethod
    def load(cls, snapshot_path: Path, sig_path: Path) -> tuple["CVEKnowledgeBase | None", str]:
        """加载并校验签名；不可用返回 (None, 原因)。"""
        if not snapshot_path.exists() or not sig_path.exists():
            return None, "CVE 快照缺失（运行 python -m knowledge.snapshot 构建）"
        data = snapshot_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sig_path.read_text(encoding="utf-8").strip():
            # HARD: 签名不匹配 → 拒绝加载（防投毒）
            warn("[CVE] 快照签名不匹配，拒绝加载（可能被篡改）")
            return None, "快照签名校验失败，已拒绝加载"
        try:
            payload = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            return None, f"快照解析失败: {exc}"
        return cls(payload.get("entries", {}), payload.get("snapshot_date", "unknown"),
                   payload.get("source", "NVD/OSV")), "ok"

    def lookup(self, product: str, version: str | None = None) -> dict:
        """检索：found / 未收录（HARD 否定证据）/ 附快照时间戳。"""
        key = product.strip().lower()
        hit = self._entries.get(key)
        if not hit:
            return {
                "status": "未收录",
                "product": product,
                "snapshot_date": self.snapshot_date,
                "note": "知识库未收录该产品，禁止推测 CVE（HARD 否定证据）",
            }
        vulns = hit if isinstance(hit, list) else hit.get("vulns", [])
        return {
            "status": "found",
            "product": product,
            "version": version or "",
            "cves": [v.get("id") for v in vulns if v.get("id")][:20],
            "snapshot_date": self.snapshot_date,
            "source": f"[来源: {self.source} 快照 {self.snapshot_date}]",
        }


class CVEQuery(BaseModel):
    """CVE 查询参数（供 Agent 工具化调用时校验）。"""

    product: str = Field(..., min_length=2, max_length=64)
    version: str = Field("", max_length=32)
