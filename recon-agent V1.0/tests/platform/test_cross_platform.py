"""跨平台专项测试（Windows / Linux 双跑；路径 / 工具发现 / 无 shell 子进程）。"""
import asyncio
import os
import sys

from platforms.paths import get_auth_dir, get_cache_dir, get_config_dir
from platforms.subprocess import run_command
from platforms.tools import find_tool


def test_config_dir_resolves_on_windows_and_linux():
    for path in (get_config_dir(), get_cache_dir(), get_auth_dir()):
        assert path.name == "recon-agent" or path.parent.name == "recon-agent"
        assert "\\" not in str(path).replace(str(path.drive), "") or os.name == "nt"


def test_tool_discovery_finds_python():
    # Windows: python.exe；Linux: python3/python —— 都必须能发现
    assert find_tool("python" if os.name == "nt" else "python3") is not None


def test_tool_discovery_finds_exe_on_windows():
    if os.name != "nt":
        return
    assert find_tool("python").endswith((".exe", ".bat", ".cmd"))


def test_subprocess_runs_without_shell():
    ret, out, err = asyncio.run(
        run_command([sys.executable, "-c", "print('ok-no-shell')"], timeout=30)
    )
    assert ret == 0 and "ok-no-shell" in out and not err


def test_subprocess_timeout_kills():
    code = "import time; time.sleep(10)"
    ret, _, err = asyncio.run(run_command([sys.executable, "-c", code], timeout=2))
    assert ret == 124 and "timeout" in err
