"""CLI → 持久化会话 → 三格式报告 → 新进程恢复。"""
import json

import pytest

pytestmark = pytest.mark.e2e

SESSION_ARGS = ("--session", "-t", "example.com", "--authorized", "--ui", "rich")


def read_report(directory):
    files = list(directory.glob("*.json"))
    assert len(files) == 1, files
    path = files[0]
    for suffix in (".json", ".md", ".csv"):
        assert path.with_suffix(suffix).stat().st_size > 0
    return json.loads(path.read_text(encoding="utf-8"))


def test_session_report_and_resume_without_model_calls(run_app, tmp_path):
    first_dir = tmp_path / "first reports"
    first = run_app(*SESSION_ARGS, "-o", str(first_dir), input_text="status\nreport\nquit\n")
    assert first.returncode == 0, first.stdout + first.stderr
    assert "等待输入" in first.stdout
    report = read_report(first_dir)
    state = report["session"]
    identifier = state["session_id"]
    assert state["target"] == "example.com"
    assert state["status"] == "idle"
    assert state["used_tokens"] == 0
    assert state["results"] == []
    assert report["metrics"]["model_calls"] == 0
    assert (tmp_path / "config" / "recon-agent" / "agent_state.sqlite").is_file()

    second_dir = tmp_path / "resumed reports"
    second = run_app(*SESSION_ARGS, "--resume", identifier, "-o", str(second_dir),
                     input_text="report\nquit\n")
    assert second.returncode == 0, second.stdout + second.stderr
    restored = read_report(second_dir)
    assert restored["session"]["session_id"] == identifier
    assert restored["session"]["task_id"] == state["task_id"]
    assert restored["session"]["used_tokens"] == 0
    assert restored["metrics"]["model_calls"] == 0


def test_unknown_session_cannot_be_resumed(run_app):
    result = run_app(*SESSION_ARGS, "--resume", "nonexistent-session", input_text="quit\n")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "会话无法打开" in result.stdout + result.stderr
