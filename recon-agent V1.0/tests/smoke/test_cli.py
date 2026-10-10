"""CLI 冒烟：真实子进程启动及参数拒绝，不触发采集。"""
import pytest

pytestmark = pytest.mark.smoke


@pytest.mark.parametrize(("args", "expected"), [
    (("--help",), "--authorized"),
    (("--version",), "recon-agent V1.0"),
    (("--list-tools",), "fingerprint"),
])
def test_cli_entrypoints(run_app, args, expected):
    result = run_app(*args)
    assert result.returncode == 0, result.stdout + result.stderr
    assert expected in result.stdout


@pytest.mark.parametrize(("args", "expected"), [
    (("-t", "example.com", "--batch"), "未获授权"),
    (("--resume", "missing"), "--resume 必须配合 --session"),
    (("--session", "--mcp"), "会话与 --mcp 不兼容"),
    (("--auth", "--batch"), "启动配置需要交互终端"),
])
def test_cli_rejects_invalid_startup(run_app, args, expected):
    result = run_app(*args)
    assert result.returncode == 2, result.stdout + result.stderr
    assert expected in result.stdout + result.stderr


def test_mcp_requires_scope(run_app):
    result = run_app(module="server.mcp_server")
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stdout == ""
    assert "--authorized-for" in result.stderr
