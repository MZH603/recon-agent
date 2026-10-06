"""沙箱三层校验测试（AST 黑名单 / Bandit 缺失拒绝 / HITL 门）。"""
import asyncio

from scripts.sandbox import execute, validate_script


def test_blocks_subprocess_import():
    assert not validate_script("import subprocess\nsubprocess.run('ls')").allowed


def test_blocks_os_and_eval():
    assert not validate_script("import os\nos.system('dir')").allowed
    assert not validate_script("eval('1+1')").allowed
    assert not validate_script("__import__('os')").allowed


def test_blocks_file_write():
    assert not validate_script("open('x.txt', 'w')").allowed
    assert not validate_script("from pathlib import Path\nPath('x').write_text('a')").allowed


def test_blocks_network_exfiltration_post():
    assert not validate_script(
        "import urllib.request\nurllib.request.Request('http://x', data=b'a')"
    ).allowed


def test_allows_readonly_socket_probe():
    script = (
        "import socket\n"
        "s = socket.create_connection(('example.com', 80), timeout=5)\n"
        "s.close()\n"
    )
    assert validate_script(script).allowed


def test_execute_requires_confirmation():
    ret, out, err = asyncio.run(execute("print('hi')", confirmed=False))
    assert ret == 125 and "未经用户确认" in err  # HARD: HITL 门


def test_execute_rejects_when_bandit_missing(monkeypatch):
    import platforms.tools as pt

    monkeypatch.setattr(pt, "find_tool", lambda name: None)  # bandit 与 docker 都缺失
    from scripts import sandbox

    monkeypatch.setattr(sandbox, "find_tool", lambda name: None)
    ret, _, err = asyncio.run(execute("print('hi')", confirmed=True))
    assert ret == 126 and "bandit" in err  # HARD: 三层缺一 → 拒绝
