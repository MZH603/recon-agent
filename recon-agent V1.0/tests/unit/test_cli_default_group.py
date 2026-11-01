"""CLI 默认命令路由测试（HARD：历史单命令用法与显式 run/cleanup 三者共存）。"""
from typer.testing import CliRunner

from cli.main import app


def test_explicit_run_command_not_double_inserted():
    """显式 `run …` 不得被再次插入 run（BUG 回归：曾出现 run run）。离线 --list-tools 验证路由。"""
    result = CliRunner().invoke(app, ["run", "--list-tools"])
    assert "run run" not in (result.output or "")
    assert "No such option" not in result.output
    assert result.exit_code == 0


def test_cleanup_subcommand_resolves():
    """cleanup 子命令正常解析（默认路由不吞掉它）。"""
    result = CliRunner().invoke(app, ["cleanup", "--help"])
    assert result.exit_code == 0
    assert "痕迹清理" in result.output


def test_top_level_help_lists_commands():
    """顶层 --help 保持组帮助（列出 run/cleanup）。"""
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "cleanup" in result.output
