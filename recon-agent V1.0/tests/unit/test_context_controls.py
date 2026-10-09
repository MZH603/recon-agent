"""Context configuration and cost controls cannot become cumulative token limits."""
import pytest
from pydantic import ValidationError
from utils.config import Settings


def test_context_defaults_and_obsolete_cli_token_limit():
    from cli.main import _settings_with
    settings = Settings()
    assert settings.CONTEXT_BUDGET == 100_000
    assert settings.COMPACT_TRIGGER_RATIO == .7
    assert _settings_with(1, None).MAX_TOKENS_PER_TASK == 0


@pytest.mark.parametrize('override', [dict(CONTEXT_BUDGET=0),
    dict(COMPACT_TRIGGER_RATIO=0), dict(COMPACT_TRIGGER_RATIO=1),
    dict(COMPACT_TRIGGER_RATIO=float('nan'))])
def test_invalid_context_settings_are_rejected(override):
    with pytest.raises(ValidationError):
        Settings(**override)


def test_cli_context_override_is_validated_before_startup(monkeypatch):
    from typer.testing import CliRunner
    from cli import main
    configured = Settings(model={'api_key': 'fixture-context-credential'})
    monkeypatch.setattr(main, '_settings_with', lambda *_: configured.model_copy(deep=True))
    runner = CliRunner()
    invalid = runner.invoke(main.app, ['--compact-ratio', 'nan', '--list-tools'])
    assert invalid.exit_code == 2
    assert '启动配置无效' in invalid.output
    seen = []
    def inventory(settings, registry):
        seen.append((settings.CONTEXT_BUDGET, settings.COMPACT_TRIGGER_RATIO))
        assert settings.model.api_key.get_secret_value() == 'fixture-context-credential'
        return []
    monkeypatch.setattr('tools.adapters.offline_status.tool_inventory', inventory)
    valid = runner.invoke(main.app, ['--context-tokens', '120000', '--compact-ratio', '.6', '--list-tools'])
    assert valid.exit_code == 0
    assert seen == [(120000, .6)]


def test_cost_command_does_not_reinterpret_legacy_tokens_as_dollars():
    from cli.session_commands import operator_command
    assert operator_command('/budget cost 1.5') == ('budget', (0, 1.5))
    for text in ('/budget 20000', '/budget 20000 1', '/budget cost nan', '/budget cost -1'):
        with pytest.raises(ValueError):
            operator_command(text)


def test_report_distinguishes_context_from_cumulative_usage():
    from core.orchestration.state import initial_state
    from output.session_report import build_session_report
    state = initial_state('report', 'example.com', '')
    state.update(status='completed', used_tokens=900_000, context_tokens=20_000,
        context_capacity=100_000, context_compactions=2, context_saved_tokens=30_000)
    data, metrics, _, _ = build_session_report(state, 0)
    assert metrics.extra['context_tokens'] == 20_000
    assert metrics.extra['context_capacity'] == 100_000
    assert metrics.extra['used_tokens'] == 900_000
    assert any('上下文' in note and '20000' in note for note in data.notes)
    assert not any('900000/0 tokens' in note for note in data.notes)
