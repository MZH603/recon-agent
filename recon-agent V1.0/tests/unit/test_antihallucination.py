"""抗幻觉模块测试（证据绑定 / 矛盾不二选一 / 一致性校验 / CVE 否定证据）。"""
import pytest
from pydantic import ValidationError

from hallucination.contradiction import ContradictionDetector
from hallucination.consistency import Finding, OutputConsistencyChecker
from hallucination.evidence import EvidenceStore, assert_grounded, bind_evidence
from knowledge.cve_base import CVEKnowledgeBase
from tools.base import ToolResult


def test_source_hash_attached_to_tool_result():
    result = bind_evidence(ToolResult(name="t", success=True), "HTTP Header", b"body-bytes")
    assert result.evidence == ["HTTP Header"]
    assert len(result.source_hash) == 64  # HARD: SHA256 前 64 字节


def test_finding_without_evidence_marked_uncertain():
    assert "[未确认，建议人工核实]" in assert_grounded("这是 WordPress", [])


def test_contradictory_sources_flagged_not_resolved():
    det = ContradictionDetector()
    det.observe("example.com", "server", "Apache", "Header")
    det.observe("example.com", "server", "Nginx", "页面特征")
    conflicts = det.conflicts()
    assert len(conflicts) == 1
    assert set(conflicts[0]["values"]) == {"Apache", "Nginx"}  # 双方都保留，不裁决


def test_report_consistency_check_removes_unsourced_items():
    checker = OutputConsistencyChecker(known_sources={"Header"})
    report = checker.check([
        Finding(subject="h", claim="Nginx", evidence=["Header"]),
        Finding(subject="h", claim="WordPress", evidence=[]),
        Finding(subject="h", claim="Ghost", evidence=["幻觉来源"]),
    ])
    assert len(report.kept) == 1
    assert any("[无证据]" in f.claim for f in report.flagged)
    assert not report.removed  # 默认标注不删除；CI 开关下可移除
    strict = checker.check([Finding(subject="h", claim="x", evidence=[])], remove_unsourced=True)
    assert strict.removed


def test_empty_cve_result_does_not_invent_id(tmp_path):
    # 快照缺失 → 不可用；空快照 → 未收录（HARD：绝不返回编造的 CVE 编号）
    kb, note = CVEKnowledgeBase.load(tmp_path / "no.json", tmp_path / "no.sig")
    assert kb is None and "缺失" in note
    (tmp_path / "s.json").write_bytes(b'{"entries": {}, "snapshot_date": "2026-01-01", "source": "t"}')
    import hashlib
    (tmp_path / "s.sig").write_text(hashlib.sha256(b'{"entries": {}, "snapshot_date": "2026-01-01", "source": "t"}').hexdigest())
    kb2, _ = CVEKnowledgeBase.load(tmp_path / "s.json", tmp_path / "s.sig")
    result = kb2.lookup("wordpress", "6.0")
    assert result["status"] == "未收录" and not result.get("cves")


def test_cve_snapshot_signature_mismatch_rejected(tmp_path):
    (tmp_path / "s.json").write_bytes(b'{"entries": {}, "snapshot_date": "x", "source": "t"}')
    (tmp_path / "s.sig").write_text("deadbeef")
    kb, note = CVEKnowledgeBase.load(tmp_path / "s.json", tmp_path / "s.sig")
    assert kb is None and "签名" in note  # HARD: 防投毒


def test_evidence_store_ids():
    store = EvidenceStore()
    eid = store.add(ToolResult(name="dns_query", success=True, evidence=["DoH"]))
    assert eid == "E1" and store.has_source("DoH")


def test_tool_result_err_is_explicit():
    result = ToolResult.err("t", "boom")
    assert not result.success and result.error == "boom"
    with pytest.raises(ValidationError):
        ToolResult(name="t")  # success 必填，杜绝含糊构造
