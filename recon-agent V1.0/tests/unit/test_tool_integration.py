import asyncio
import json

import pytest
from pydantic import BaseModel
from typer.testing import CliRunner

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.base import BaseTool, ToolResult
from tools.registry import ToolRegistry, build_default
from utils.config import Settings


@pytest.fixture(autouse=True)
def fresh_console(monkeypatch):
    # MCP serve switches process-global logger streams; isolate CLI assertions.
    monkeypatch.setattr('utils.logger._console', None)
    monkeypatch.setattr('utils.logger._stderr_mode', False)


class Params(BaseModel):
    target: str


class DeferredTool(BaseTool):
    name = 'extra_fixture'
    description = 'Offline extra fixture for catalog selection'
    params_model = Params
    deferred = True
    def __init__(self):
        self.closed = 0
    async def run(self, params):
        return ToolResult(name=self.name, success=True, evidence=['fixture://extra'])
    async def aclose(self):
        self.closed += 1


def names(specs):
    return {s['function']['name'] for s in specs}


def test_deferred_selection_catalog_and_close(tmp_path):
    async def scenario():
        settings = Settings()
        registry = build_default(settings, ScanGate('example.com', auth_dir=tmp_path), 'example.com')
        tool = DeferredTool()
        registry.register(tool)
        assert tool.name not in names(registry.specs())
        assert tool.name in names(registry.specs(include_deferred=True))
        result = await registry.execute(NormalizedToolCall(id='select', name='tool_catalog',
            arguments={'target': 'example.com', 'query': 'extra', 'select': [tool.name]}))
        assert result.success and result.data['selected_tools'] == [tool.name]
        assert tool.name in names(registry.specs())
        registry.select_tools([])
        assert tool.name not in names(registry.specs())
        await registry.aclose()
        await registry.aclose()
        assert tool.closed == 1
    asyncio.run(scenario())


def test_extensions_validate_collisions_and_disabled_config(tmp_path):
    with pytest.raises(ValueError):
        Settings(custom_tools=[{'name': 'bad', 'kind': 'command', 'command': ['echo'], 'min_level': 0}])
    disabled = Settings(mcp_servers=[{'name': 'browser', 'enabled': False, 'transport': 'stdio', 'command': 'missing'}])
    registry = build_default(disabled, ScanGate('example.com', auth_dir=tmp_path), 'example.com')
    assert 'mcp_call' not in registry.names()
    settings = Settings(custom_tools=[{'name': 'dns_query', 'kind': 'command', 'command': ['echo']}])
    with pytest.raises(ValueError, match='dns_query'):
        build_default(settings, ScanGate('example.com', auth_dir=tmp_path), 'example.com')


def test_list_tools_is_offline_and_config_errors_are_concise(tmp_path):
    from cli.main import app
    path = tmp_path / 'tools.yaml'
    path.write_text('custom_tools:\n  - name: my_command\n    kind: command\n    command: [missing-executable, "{target}"]\n', encoding='utf-8')
    result = CliRunner().invoke(app, ['--tools-config', str(path), '--list-tools'])
    assert result.exit_code == 0, result.output
    assert 'my_command' in result.output and 'api_recon' in result.output
    path.write_text('GATE_PER_STEP_CONFIRM: false\n', encoding='utf-8')
    result = CliRunner().invoke(app, ['--tools-config', str(path), '--list-tools'])
    assert result.exit_code == 2
    assert 'GATE_PER_STEP_CONFIRM' in result.output


def test_bridge_lists_deferred_and_keeps_authorized_root(tmp_path):
    from server.tools_bridge import MCPBridge
    bridge = MCPBridge(Settings(), ['example.com'])
    registry = bridge._registry()
    registry.register(DeferredTool())
    assert registry.main_target == 'example.com'
    assert 'extra_fixture' in {s['name'] for s in bridge.tool_schemas()}
    asyncio.run(bridge.aclose())


def test_selection_survives_runtime_restart_and_registry_closes(tmp_path):
    from core.orchestration import SessionRuntime
    from tests.unit.test_session_graph import ScriptedLLM, response
    async def scenario():
        settings = Settings()
        def runtime(llm):
            gate = ScanGate('example.com', auth_dir=tmp_path / 'auth')
            registry = build_default(settings, gate, 'example.com')
            tool = DeferredTool()
            registry.register(tool)
            return SessionRuntime(target='example.com', registry=registry, llm=llm, gate=gate,
                settings=settings, db_path=tmp_path / 'session.db', session_id='selection'), tool
        first, tool = runtime(ScriptedLLM(response('tool_catalog', {'target': 'example.com', 'select': ['extra_fixture']}),
            response('ask_user', {'question': 'Continue?'})))
        async with first:
            state = await first.submit('Select extension')
            assert state['selected_tool_names'] == ['extra_fixture']
        assert tool.closed == 1
        second, second_tool = runtime(ScriptedLLM())
        async with second:
            assert (await second.state())['selected_tool_names'] == ['extra_fixture']
            assert 'extra_fixture' in names(second.registry.specs())
        assert second_tool.closed == 1
    asyncio.run(scenario())


def test_api_findings_reported_with_candidate_status(tmp_path):
    from output.session_report import save_session_report
    endpoint = {'method': 'GET', 'path': '/api/items', 'params': ['page'], 'source': 'https://example.com/app.js', 'observed': False}
    state = {'target': 'example.com', 'session_id': 'api', 'status': 'completed',
        'results': [ToolResult(name='api_recon', success=True,
            data={'endpoints': [endpoint], 'frontend_routes': ['/dashboard']}, evidence=['evidence://abc']).model_dump()]}
    paths = save_session_report(state, out_dir=tmp_path)
    payload = json.loads(paths['json'].read_text(encoding='utf-8'))
    assert payload['report']['api_endpoints'] == [endpoint]
    assert payload['report']['frontend_routes'] == ['/dashboard']
    markdown = paths['markdown'].read_text(encoding='utf-8')
    assert '/api/items' in markdown and '候选' in markdown
    assert '/api/items' in paths['csv'].read_text(encoding='utf-8')


def test_configured_command_uses_session_l2_gate_and_saved_report(tmp_path):
    import sys
    from core.orchestration import SessionRuntime
    from output.session_report import save_session_report
    from tests.unit.test_session_graph import ScriptedLLM, response
    async def scenario():
        settings = Settings(TOOL_EVIDENCE_DIR=str(tmp_path / 'evidence'), custom_tools=[{
            'name': 'local_check', 'kind': 'command', 'command': [sys.executable, '-c', 'print(42)'],
            'response_format': 'json'}])
        gate = ScanGate('example.com', auth_dir=tmp_path / 'auth')
        registry = build_default(settings, gate, 'example.com')
        llm = ScriptedLLM(response('tool_catalog', {'target': 'example.com', 'select': ['local_check']}),
            response('local_check', {'target': 'example.com'}), response('ask_user', {'question': 'Review result?'}))
        async with SessionRuntime(target='example.com', registry=registry, llm=llm, gate=gate,
            settings=settings, db_path=tmp_path / 'command.db', session_id='command') as runtime:
            state = await runtime.submit('Run configured offline check')
            assert state['pending']['kind'] == 'authorization'
            assert not (tmp_path / 'evidence').exists()
            for answer in ('CONFIRM 2', 'example.com', 'I UNDERSTAND AND AUTHORIZE'):
                state = await runtime.resume(answer)
            assert not (tmp_path / 'evidence').exists()
            state = await runtime.resume('yes')
            result = next(r for r in state['results'] if r['name'] == 'local_check')
            assert result['success'] and result['data']['output'] == 42
            assert result['source_hash'] and result['evidence']
            paths = save_session_report(state, out_dir=tmp_path / 'reports')
            saved = json.loads(paths['json'].read_text(encoding='utf-8'))
            assert any(r['name'] == 'local_check' and r['data']['output'] == 42 for r in saved['observations'])
    asyncio.run(scenario())


def test_tools_config_preserves_in_memory_credentials(tmp_path):
    from tools.integration_loader import load_tools_config
    from utils.config import ModelConfig
    settings = Settings(model=ModelConfig(api_key='test-secret', custom_endpoints=[{'name': 'other', 'api_key': 'other-secret'}]))
    path = tmp_path / 'extensions.yaml'
    path.write_text('custom_tools: []\n', encoding='utf-8')
    loaded = load_tools_config(settings, path)
    assert loaded.model.api_key.get_secret_value() == 'test-secret'
    assert loaded.model.custom_endpoints[0]['api_key'].get_secret_value() == 'other-secret'
    assert loaded.model is not settings.model


def test_cli_cascade_receives_tools_and_lab_settings(tmp_path, monkeypatch):
    from cli.main import app
    received = []
    async def cascade(**kwargs):
        received.append(kwargs.get('settings'))
        return 0
    monkeypatch.setattr('scripts.full_scan.run', cascade)
    path = tmp_path / 'tools.yaml'
    path.write_text('custom_tools:\n  - name: injected\n    kind: command\n    command: [echo]\n', encoding='utf-8')
    result = CliRunner().invoke(app, ['--authorized', '-t', 'example.com', '--level', '1', '--lab',
        '--tools-config', str(path)])
    assert result.exit_code == 0, result.output
    assert received[0] is not None and received[0].LAB_MODE
    assert received[0].custom_tools[0].name == 'injected'


def test_session_startup_failure_still_closes_registry(tmp_path):
    from core.orchestration import SessionRuntime
    from tests.unit.test_session_graph import ScriptedLLM
    async def scenario():
        gate = ScanGate('example.com', auth_dir=tmp_path / 'auth')
        registry = ToolRegistry(Settings(), gate, 'example.com')
        tool = DeferredTool(); registry.register(tool)
        runtime = SessionRuntime(target='example.com', registry=registry, llm=ScriptedLLM(), gate=gate,
            settings=Settings(), db_path=tmp_path / 'missing.db', session_id='missing', require_existing=True)
        with pytest.raises(ValueError, match='does not exist'):
            async with runtime:
                pass
        assert tool.closed == 1
    asyncio.run(scenario())


def test_mcp_stdio_eof_closes_bridge(monkeypatch):
    import io
    from server import mcp_server
    closed = []
    class Bridge:
        def __init__(self, *args):
            pass
        async def aclose(self):
            closed.append(True)
    monkeypatch.setattr(mcp_server, 'MCPBridge', Bridge)
    monkeypatch.setattr(mcp_server.sys, 'stdin', io.StringIO(''))
    assert asyncio.run(mcp_server.serve(['example.com'], settings=Settings())) == 0
    assert closed == [True]


def test_stateful_tool_results_are_not_reused_by_argument_signature(tmp_path):
    from tests.unit.test_session_graph import ScriptedLLM, fixture, response
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}, 'first'),
            response('fixture', {'target': 'example.com'}, 'second'), response('ask_user', {'question': 'Done?'}))
        runtime, tool, _ = fixture(tmp_path, llm)
        tool.cacheable = False
        async with runtime:
            state = await runtime.submit('Read evolving state twice')
            assert tool.calls == 2
            assert not state['results'][1].get('cached', False)
    asyncio.run(scenario())


def test_noncacheable_journal_preserves_recovery_and_uncertain_guard(tmp_path):
    from core.orchestration.store import SessionStore
    async def scenario():
        store = await SessionStore(tmp_path / 'journal.db').open()
        try:
            arguments = {'target': 'example.com'}
            await store.start('s', 'done', 'mcp_call', arguments, 'task')
            await store.complete('s', 'done', {'success': True, 'data': {'page': 'old'}})
            assert await store.lookup('s', 'next', 'mcp_call', arguments, 'task', reuse_completed=False) is None
            assert (await store.lookup('s', 'done', 'mcp_call', arguments, 'task', reuse_completed=False))['status'] == 'completed'
            await store.start('s', 'uncertain', 'mcp_call', arguments, 'task')
            assert (await store.lookup('s', 'next', 'mcp_call', arguments, 'task', reuse_completed=False))['status'] == 'started'
        finally:
            await store.close()
    asyncio.run(scenario())


def test_offline_inventory_includes_disabled_and_missing_connectors(tmp_path):
    from cli.main import app
    path = tmp_path / 'tools.yaml'
    path.write_text('custom_tools:\n  - name: missing_local_tool\n    kind: command\n    command: [recon_nonexistent_test_binary]\nmcp_servers:\n  - name: disabled_browser\n    enabled: false\n    command: node\n', encoding='utf-8')
    result = CliRunner().invoke(app, ['--tools-config', str(path), '--list-tools'])
    assert result.exit_code == 0, result.output
    assert 'missing-executable' in result.output
    assert 'disabled_browser' in result.output and 'disabled' in result.output


@pytest.mark.parametrize('name', ['finish_task', 'ask_user', 'update_plan', 'recon_safety_policy'])
def test_custom_names_cannot_collide_with_session_controls(tmp_path, name):
    settings = Settings(custom_tools=[{'name': name, 'kind': 'command', 'command': ['echo']}])
    with pytest.raises(ValueError, match=name):
        build_default(settings, ScanGate('example.com', auth_dir=tmp_path), 'example.com')
