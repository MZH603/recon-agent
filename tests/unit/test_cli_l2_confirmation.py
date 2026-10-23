import sys
from types import ModuleType

from typer.testing import CliRunner

from cli.main import app


def test_non_tty_does_not_implicitly_auto_confirm_l2(monkeypatch):
    captured = {}

    async def fake_cascade(**kwargs):
        captured.update(kwargs)
        return 0

    async def no_op(**kwargs):
        return 0

    fake_full_scan = ModuleType("scripts.full_scan")
    fake_full_scan.run = fake_cascade
    fake_pipeline = ModuleType("cli.pipeline")
    fake_pipeline.run_pipeline = no_op
    fake_session = ModuleType("cli.session")
    fake_session.run_session = no_op
    monkeypatch.setitem(sys.modules, "scripts.full_scan", fake_full_scan)
    monkeypatch.setitem(sys.modules, "cli.pipeline", fake_pipeline)
    monkeypatch.setitem(sys.modules, "cli.session", fake_session)

    result = CliRunner().invoke(
        app,
        ["--target", "example.com", "--authorized", "--level", "2"],
    )

    assert result.exit_code == 0, result.output
    assert captured["auto_confirm"] is False
