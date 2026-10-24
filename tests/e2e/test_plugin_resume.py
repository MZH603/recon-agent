"""Plugin identity is pinned before resumed sessions can run work."""
import asyncio
import sys
from types import ModuleType

import pytest

from agent.plugins.api import PluginManifest
from agent.plugins.context import ContextBlock
from agent.model.base import LLMResponse, NormalizedToolCall
from agent.utils.config import Settings

from test_loop_runtime import make_runtime


class Source:
    required = False

    def __init__(self, version='1.0', ident='session-source'):
        self.manifest = PluginManifest(id=ident, version=version,
            api_version='1.0', capabilities=('context',))
        self.starts = 0

    def register(self, host, config): pass

    async def start(self, view): self.starts += 1

    async def close(self): pass

    def collect(self, view):
        return [ContextBlock(id=self.manifest.id, source=self.manifest.id, trust='internal',
            priority=1, content='source', required=False)]


def plugin_settings(monkeypatch, provider, config=None):
    module = ModuleType('test_resume_source')
    module.plugin = provider
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return Settings(plugins=[{'id': 'session-source', 'module': module.__name__,
                              'config': config or {}}])


def test_checkpoint_pins_plugin_identity_version_and_config(tmp_path, monkeypatch):
    source = Source()
    settings = plugin_settings(monkeypatch, source, {'label': 'first'})
    runtime, _ = make_runtime(tmp_path, settings, [])

    async def run():
        async with runtime:
            state = await runtime.state()
            entry = next(p for p in state['plugin_snapshot'] if p['id'] == 'session-source')
            assert entry['version'] == '1.0'
            assert len(entry['config_digest']) == 64
            assert source.starts == 1
    asyncio.run(run())


@pytest.mark.parametrize('changed', ['missing', 'version', 'config'])
def test_resume_rejects_changed_plugin_before_start_or_action(tmp_path, monkeypatch, changed):
    source = Source()
    original = plugin_settings(monkeypatch, source, {'label': 'first'})
    runtime, _ = make_runtime(tmp_path, original, [])

    async def first():
        async with runtime:
            assert (await runtime.state())['executions'] == []
    asyncio.run(first())

    replacement = Source('2.0' if changed == 'version' else '1.0')
    settings = Settings() if changed == 'missing' else plugin_settings(
        monkeypatch, replacement, {'label': 'second' if changed == 'config' else 'first'})
    resumed, model = make_runtime(tmp_path, settings, [], resume=True)

    async def second():
        with pytest.raises(ValueError, match='session-source'):
            async with resumed:
                pytest.fail('Changed plugin must not start')
    asyncio.run(second())
    assert replacement.starts == 0
    assert model.requests == []


def test_legacy_checkpoint_maps_to_builtin_plugins(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(), [])

    async def first():
        async with runtime:
            await runtime.graph.aupdate_state(runtime.config, {'plugin_snapshot': None}, as_node='decide')
    asyncio.run(first())
    resumed, _ = make_runtime(tmp_path, Settings(), [], resume=True)

    async def second():
        async with resumed:
            state = await resumed.state()
            assert {entry['id'] for entry in state['plugin_snapshot']} == {
                'builtin-tools', 'builtin-context', 'builtin-react'}
    asyncio.run(second())


def test_declared_migration_updates_plugin_state_before_start(tmp_path, monkeypatch):
    original = plugin_settings(monkeypatch, Source('1.0'))
    runtime, _ = make_runtime(tmp_path, original, [])

    async def first():
        async with runtime:
            await runtime.graph.aupdate_state(runtime.config,
                {'loop_state': {'session-source': {'cursor': 7}}}, as_node='decide')
    asyncio.run(first())

    class Migrated(Source):
        def migrate_state(self, stored_version, state):
            assert stored_version == '1.0'
            return {'cursor': state['cursor'], 'format': 2}

    replacement = Migrated('2.0')
    settings = plugin_settings(monkeypatch, replacement)
    resumed, _ = make_runtime(tmp_path, settings, [], resume=True)

    async def second():
        async with resumed:
            state = await resumed.state()
            assert state['loop_state']['session-source'] == {'cursor': 7, 'format': 2}
            assert next(p for p in state['plugin_snapshot'] if p['id'] == 'session-source')['version'] == '2.0'
    asyncio.run(second())
    assert replacement.starts == 1


def test_failed_migration_preserves_checkpoint_and_does_not_start(tmp_path, monkeypatch):
    settings = plugin_settings(monkeypatch, Source('1.0'))
    runtime, _ = make_runtime(tmp_path, settings, [])

    async def first():
        async with runtime:
            await runtime.graph.aupdate_state(runtime.config,
                {'loop_state': {'session-source': {'cursor': 7}}}, as_node='decide')
    asyncio.run(first())

    class Broken(Source):
        def migrate_state(self, stored_version, state):
            raise RuntimeError('cannot migrate')

    replacement = Broken('2.0')
    resumed, _ = make_runtime(tmp_path, plugin_settings(monkeypatch, replacement), [], resume=True)

    async def second():
        with pytest.raises(ValueError, match='session-source.*migration'):
            async with resumed:
                pytest.fail('Migration failure must block startup')
    asyncio.run(second())
    assert replacement.starts == 0

    old, _ = make_runtime(tmp_path, plugin_settings(monkeypatch, Source('1.0')), [], resume=True)

    async def verify():
        async with old:
            assert (await old.state())['loop_state']['session-source'] == {'cursor': 7}
    asyncio.run(verify())


def test_migration_does_not_skip_pending_validation(tmp_path, monkeypatch):
    initial = plugin_settings(monkeypatch, Source('1.0'))
    runtime, _ = make_runtime(tmp_path, initial, [LLMResponse(tool_calls=[
        NormalizedToolCall(id='outside', name='dns_query',
            arguments={'target': 'outside.example.org', 'record_type': 'A'})])])

    async def first():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'validation'
            assert state['executions'] == []
    asyncio.run(first())

    class Migrated(Source):
        def migrate_state(self, stored_version, state): return state

    resumed, model = make_runtime(tmp_path, plugin_settings(monkeypatch, Migrated('2.0')),
        [LLMResponse(content='Done\n<task_complete/>')], resume=True)

    async def second():
        async with resumed:
            state = await resumed.state()
            assert state['pending']['kind'] == 'validation'
            assert state['executions'] == []
            state = await resumed.resume('Continue')
            assert state['status'] == 'completed'
            assert state['executions'] == []
    asyncio.run(second())
    assert len(model.requests) == 1


def test_builtin_tool_configuration_is_pinned(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(), [])

    async def first():
        async with runtime:
            pass
    asyncio.run(first())

    changed = Settings(extension_tools={'knowledge_enabled': False})
    resumed, _ = make_runtime(tmp_path, changed, [], resume=True)

    async def second():
        with pytest.raises(ValueError, match='builtin-tools config changed'):
            async with resumed:
                pytest.fail('Changed built-in tool catalog must not resume')
    asyncio.run(second())


def test_plugin_order_cannot_change_when_resuming(tmp_path, monkeypatch):
    module_a = ModuleType('test_source_a')
    module_b = ModuleType('test_source_b')
    module_a.plugin = Source(ident='source-a')
    module_b.plugin = Source(ident='source-b')
    monkeypatch.setitem(sys.modules, module_a.__name__, module_a)
    monkeypatch.setitem(sys.modules, module_b.__name__, module_b)
    entries = [{'id': 'source-a', 'module': module_a.__name__},
               {'id': 'source-b', 'module': module_b.__name__}]
    runtime, _ = make_runtime(tmp_path, Settings(plugins=entries), [])

    async def first():
        async with runtime:
            pass
    asyncio.run(first())

    resumed, _ = make_runtime(tmp_path, Settings(plugins=list(reversed(entries))), [], resume=True)

    async def second():
        with pytest.raises(ValueError, match='order'):
            async with resumed:
                pytest.fail('Plugin ordering is part of the pinned session configuration')
    asyncio.run(second())
