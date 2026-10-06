"""CLI 集成冒烟：入口可运行、--help 正常（不触网）。"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_cli_help_runs():
    ret = subprocess.run(
        [sys.executable, "-m", "cli.main", "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
    )
    assert ret.returncode == 0
    assert "--authorized" in ret.stdout


def test_cli_batch_without_authorization_rejected():
    # HARD: batch 且未 --authorized → 拒绝（退出码 2）
    ret = subprocess.run(
        [sys.executable, "-m", "cli.main", "-t", "example.com", "--batch"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
    )
    assert ret.returncode == 2
