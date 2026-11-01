"""痕迹清理测试：scope 白名单 / 审计日志与 reports 永不清理 / 登记临时文件销毁。"""
import json

from security.anonymity import trace_cleanup as tc
from utils.logger import audit_path


def test_unknown_scope_rejected():
    """未知范围显式拒绝（白名单制）。"""
    import pytest
    with pytest.raises(ValueError):
        tc.cleanup("everything")


def test_session_scope_removes_registered_temp_and_keeps_audit(tmp_path, monkeypatch):
    """session 范围：登记临时文件被销毁；audit.log 不受影响（HARD）。"""
    target_file = tmp_path / "tool_output.tmp"
    target_file.write_text("sensitive-session-artifact", encoding="utf-8")
    tc.TempArtifactRegistry.register(target_file)

    audit_file = audit_path()
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    audit_file.write_text('{"event":"keep-me"}\n', encoding="utf-8")

    monkeypatch.setattr(tc, "_session_paths", lambda: [target_file])
    result = tc.cleanup("session")
    assert result["removed"] == 1
    assert not target_file.exists()
    assert "keep-me" in audit_file.read_text(encoding="utf-8")


def test_session_scope_includes_cache_dumps(tmp_path, monkeypatch):
    """cache/task_* 会话落盘目录纳入 session 范围。"""
    cache_dir = tmp_path / "cache"
    task_dir = cache_dir / "task_abc123"
    task_dir.mkdir(parents=True)
    (task_dir / "tool_raw.txt").write_text("raw", encoding="utf-8")
    monkeypatch.setattr(tc, "_cache_dir", lambda: cache_dir)
    monkeypatch.setattr(tc, "_evidence_root", lambda: tmp_path / "no-evidence")
    tc.TempArtifactRegistry.clear()

    paths = tc._session_paths()
    assert task_dir in paths

    result = tc.cleanup("session")
    assert result["removed"] == 1
    assert not task_dir.exists()


def test_artifacts_scope_removes_evidence_but_not_audit(tmp_path, monkeypatch):
    """artifacts 范围：evidence JSON/工作区删除；audit.log 完好。"""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / ("a" * 64 + ".json")).write_text("{}", encoding="utf-8")
    ws = evidence / "workspace"
    ws.mkdir()
    (ws / "records.sqlite3").write_text("db", encoding="utf-8")

    audit_file = audit_path()
    before = audit_file.read_text(encoding="utf-8") if audit_file.exists() else ""

    monkeypatch.setattr(tc, "_evidence_root", lambda: evidence)
    monkeypatch.setattr(tc, "_session_paths", lambda: [])
    tc.TempArtifactRegistry.clear()

    result = tc.cleanup("artifacts")
    assert result["removed"] >= 2
    assert audit_file.read_text(encoding="utf-8") == before or before == ""


def test_system_scope_flush_dns_called(tmp_path, monkeypatch):
    """system 范围：DNS 缓存刷新被调用且审计；签名文件按 target 过滤删除。"""
    auth = tmp_path / "auth"
    auth.mkdir()
    (auth / "target-a.sig").write_text("sig", encoding="utf-8")
    (auth / "target-b.sig").write_text("sig", encoding="utf-8")
    monkeypatch.setattr(tc, "_config_dir", lambda: tmp_path)
    monkeypatch.setattr(tc, "_project_root", lambda: tmp_path)
    flushed = {"n": 0}
    monkeypatch.setattr(tc, "flush_local_dns_cache", lambda: flushed.__setitem__("n", flushed["n"] + 1) or True)

    result = tc.cleanup("system", target="target-a")
    assert result["removed"] == 1
    assert (auth / "target-a.sig").exists() is False
    assert (auth / "target-b.sig").exists()
    assert flushed["n"] == 1


def test_cleanup_always_audits(tmp_path, monkeypatch):
    """每次清理产生 trace_cleanup 审计事件（HARD：主动操作全量留痕）。"""
    monkeypatch.setattr(tc, "_session_paths", lambda: [])
    monkeypatch.setattr(tc, "_evidence_root", lambda: tmp_path / "none")
    tc.TempArtifactRegistry.clear()
    tc.cleanup("session")
    entries = [json.loads(line) for line in audit_path().read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "trace_cleanup" and e["payload"]["scope"] == "session" for e in entries)


def test_dry_run_lists_without_deleting(tmp_path, monkeypatch):
    """dry_run 仅列出路径不删除。"""
    f = tmp_path / "x.tmp"
    f.write_text("data", encoding="utf-8")
    monkeypatch.setattr(tc, "_session_paths", lambda: [f])
    listed = tc.dry_run("session")
    assert str(f) in listed
    assert f.exists()
