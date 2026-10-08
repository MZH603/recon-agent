import asyncio
import json
import pytest

from typer.testing import CliRunner

from cli import session
from cli.main import app
from model.base import LLMResponse, NormalizedToolCall
from utils.config import Settings


@pytest.fixture(autouse=True)
def fresh_console(monkeypatch):
    # MCP tests can leave a Console bound to a previous pytest capture stream.
    monkeypatch.setattr('utils.logger._console', None)


class ScriptedInput:
    def __init__(self, *lines):
        self.lines = iter(lines)

    def __call__(self, prompt):
        try:
            return next(self.lines)
        except StopIteration:
            raise EOFError


def run(tmp_path, monkeypatch, lines, factory, **kwargs):
    monkeypatch.setattr('platforms.paths.get_config_dir', lambda: tmp_path)
    return asyncio.run(session.run_session(target='example.com', settings=Settings(), batch=False,
        is_tty=True, requested_level=2, model_override=None, output_format='json', output_dir=str(tmp_path),
        input_fn=ScriptedInput(*lines), llm_factory=factory, **kwargs))


def test_idle_startup_never_constructs_model(tmp_path, monkeypatch, capsys):
    def forbidden(*args):
        raise AssertionError('idle startup constructed model')
    assert run(tmp_path, monkeypatch, ['status', 'quit'], forbidden, session_id='idle') == 0
    captured = capsys.readouterr()
    assert 'L0' in captured.out + captured.err
    assert run(tmp_path, monkeypatch, ['quit'], forbidden, resume_id='idle') == 0


def test_lazy_configuration_failure_is_paused_and_report_never_retries(tmp_path, monkeypatch):
    calls = []
    def broken(*args):
        calls.append(1)
        raise ValueError('missing model configuration')
    assert run(tmp_path, monkeypatch, ['检查目标', 'report', 'quit'], broken, session_id='broken') == 0
    assert calls == [1]
    saved = list(tmp_path.glob('**/*.json'))
    payload = json.loads(saved[-1].read_text(encoding='utf-8'))
    assert payload['session']['pending']['kind'] == 'model_unavailable'
    assert run(tmp_path, monkeypatch, ['report', 'quit'], broken, resume_id='broken') == 0
    assert calls == [1]


def test_plain_model_question_is_shown_unverified_and_replies_resume(tmp_path, monkeypatch, capsys):
    class Provider:
        def __init__(self, *args):
            self.calls = 0
        async def complete(self, messages, tools):
            self.calls += 1
            if self.calls == 1:
                return LLMResponse(content='你想查询 DNS 还是 HTTP？')
            assert messages[-1]['content'] == '只解释 DNS'
            return LLMResponse(tool_calls=[NormalizedToolCall(id='done', name='finish_task',
                arguments={'answer': 'DNS说明', 'clarification_only': True})])
    assert run(tmp_path, monkeypatch, ['帮我看看', '只解释 DNS', 'abort', 'status', 'quit'], Provider) == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert '你想查询 DNS' in text and '未验证' in text and 'DNS说明' in text


def test_cli_rejects_resume_without_session_and_session_mcp():
    runner = CliRunner()
    assert runner.invoke(app, ['-t', 'example.com', '--authorized', '--resume', 'missing']).exit_code == 2
    assert runner.invoke(app, ['--session', '--mcp', '--authorized-for', 'example.com']).exit_code == 2


def test_missing_resume_and_target_mismatch_do_not_construct_model(tmp_path, monkeypatch):
    def forbidden(*args):
        raise AssertionError('unexpected model')
    assert run(tmp_path, monkeypatch, ['quit'], forbidden, resume_id='absent') == 2
    assert run(tmp_path, monkeypatch, ['quit'], forbidden, session_id='saved') == 0
    monkeypatch.setattr('platforms.paths.get_config_dir', lambda: tmp_path)
    assert asyncio.run(session.run_session('outside.example', Settings(), False, True, 0, None,
        'json', str(tmp_path), resume_id='saved', input_fn=ScriptedInput('quit'), llm_factory=forbidden)) == 2


def test_l2_codes_remain_independent_report_is_readonly(tmp_path, monkeypatch):
    from tests.unit.test_session_graph import FakeTool, response
    from tools.registry import ToolRegistry
    tool = FakeTool(level=2)
    def registry(settings, gate, target):
        reg = ToolRegistry(settings, gate, target)
        reg.register(tool)
        return reg
    monkeypatch.setattr('tools.registry.build_default', registry)
    class Provider:
        def __init__(self, *args):
            self.responses = iter([response('fixture', {'target': 'example.com'}),
                                   response('ask_user', {'question': 'Next?'})])
        async def complete(self, *args):
            return next(self.responses)
    lines = ['inspect', 'report', 'CONFIRM 2', 'example.com',
             'I UNDERSTAND AND AUTHORIZE', 'yes', 'quit']
    assert run(tmp_path, monkeypatch, lines, Provider, session_id='l2') == 0
    assert tool.calls == 1


def test_pending_kind_is_displayed_literally(capsys):
    from gate.scan_gate import ScanGate
    session.show_state({'status': 'paused', 'pending': {'kind': 'model_unavailable',
        'question': 'test [unknown] question'}}, ScanGate('example.com'))
    captured=capsys.readouterr()
    assert '[model_unavailable]' in captured.out + captured.err
    assert '[unknown]' in captured.out + captured.err


def test_model_cancellation_closes_checkpoint_without_losing_pending(tmp_path, monkeypatch):
    class CancelledProvider:
        def __init__(self, *args):
            pass
        async def complete(self, *args):
            raise asyncio.CancelledError
    assert run(tmp_path, monkeypatch, ['inspect'], CancelledProvider, session_id='cancelled') == 130
    def forbidden(*args):
        raise AssertionError('resume startup called model')
    assert run(tmp_path, monkeypatch, ['report', 'quit'], forbidden, resume_id='cancelled') == 0
    payloads=[json.loads(p.read_text(encoding='utf-8')) for p in tmp_path.glob('*.json')]
    assert any(p['session']['pending']['kind'] == 'recovery' for p in payloads)


def test_unexpected_provider_failure_is_resumable_model_unavailable(tmp_path, monkeypatch):
    class BrokenProvider:
        def __init__(self, *args):
            pass
        async def complete(self, *args):
            raise OSError('offline endpoint')
    assert run(tmp_path, monkeypatch, ['inspect', 'report', 'quit'], BrokenProvider, session_id='provider-broken') == 0
    payloads=[json.loads(p.read_text(encoding='utf-8')) for p in tmp_path.glob('*.json')]
    assert payloads[-1]['session']['pending']['kind'] == 'model_unavailable'


def test_actual_task_cancellation_preserves_recovery_and_releases_owner(tmp_path, monkeypatch):
    monkeypatch.setattr('platforms.paths.get_config_dir', lambda: tmp_path)
    async def scenario():
        started=asyncio.Event()
        class WaitingProvider:
            def __init__(self, *args):
                pass
            async def complete(self, *args):
                started.set()
                await asyncio.Event().wait()
        task=asyncio.create_task(session.run_session('example.com', Settings(), False, True, 0, None,
            'json', str(tmp_path), session_id='real-cancel', input_fn=ScriptedInput('inspect'), llm_factory=WaitingProvider))
        await started.wait()
        task.cancel()
        assert await task == 130
    asyncio.run(scenario())
    def forbidden(*args):
        raise AssertionError('must wait')
    assert run(tmp_path, monkeypatch, ['report', 'quit'], forbidden, resume_id='real-cancel') == 0


def test_format_alias_and_auto_confirm_cannot_add_session_permissions(monkeypatch):
    captured=[]
    async def fake_run_session(**kwargs):
        captured.append(kwargs)
        return 0
    monkeypatch.setattr('cli.session.run_session', fake_run_session)
    result=CliRunner().invoke(app, ['--session','-t','example.com','--authorized','--level','2',
        '--auto-confirm','--format','json'])
    assert result.exit_code == 0
    assert captured[0]['output_format'] == 'json'
    assert 'auto_confirm' not in captured[0]
