"""通过 Node 子进程验证真实 TUI 页面启动、桥接、渲染和退出。"""
from pathlib import Path
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.smoke
ROOT = Path(__file__).resolve().parents[2]


def test_tui_process_smoke(app_env):
    node = shutil.which("node")
    assert node, "TUI 冒烟需要 Node.js >=22.19.0，请先安装 Node.js。"
    result = subprocess.run(
        [node, "--test", str(ROOT / "tests/smoke/tui_smoke.test.mjs")],
        cwd=ROOT, env=app_env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=50,
    )
    assert result.returncode == 0, result.stdout + result.stderr
