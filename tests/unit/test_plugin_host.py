import asyncio
import sys
from types import ModuleType

import pytest
from pydantic import BaseModel, ConfigDict

from agent.gate.scan_gate import ScanGate
from agent.plugins.api import PluginManifest
from agent.plugins.host import PluginHost
from agent.server.tools_bridge import MCPBridge
from agent.tools.registry import ToolRegistry, build_default
from agent.utils.config import Settings


class StrictConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token: str


class Provider:
    def __init__(self, name, *, dependencies=(), config_model=None, events=None, fail_start=False):
        self.manifest = PluginManifest(id=name, version='1.0', api_version='1.0',
            capabilities=('tools',), config_model=config_model, dependencies=dependencies)
        self.events = events if events is not None else []
        self.fail_start = fail_start

    def register(self, host, validated_config):
        self.events.append(('register', self.manifest.id, validated_config))

    def describe_tool_names(self, validated_config):
        return ()

    async def start(self, session_view):
        self.events.append(('start', self.manifest.id))
        if self.fail_start:
            raise RuntimeError('startup failed')

    async def close(self):
        self.events.append(('close', self.manifest.id))


def host(settings=None):
    settings = settings or Settings()
    gate = ScanGate('example.com', batch_mode=True, is_tty=False)
    return PluginHost(ToolRegistry(settings, gate, 'example.com'))


def test_manifest_rejects_invalid_api_and_ids():
    with pytest.raises(ValueError):
        PluginManifest(id='Bad ID', version='1', api_version='1.0', capabilities=('tools',))
    with pytest.raises(ValueError):
        PluginManifest(id='good', version='1', api_version='2.0', capabilities=('tools',))


def test_invalid_config_and_missing_dependencies_register_nothing():
    events = []
    first = Provider('first', events=events)
    second = Provider('second', config_model=StrictConfig, events=events)
    with pytest.raises(ValueError, match='second'):
        host().load([(first, {}), (second, {'token': 'ok', 'other': 1})])
    assert events == []
    with pytest.raises(ValueError, match='missing'):
        host().load([(Provider('dependent', dependencies=('missing',), events=events), {})])
    assert events == []


def test_missing_lifecycle_method_registers_nothing():
    events = []
    incomplete = Provider('incomplete', events=events)
    incomplete.close = None
    with pytest.raises(ValueError, match='close'):
        host().load([(Provider('first', events=events), {}), (incomplete, {})])
    assert events == []


def test_cycle_and_duplicate_ids_register_nothing():
    events = []
    with pytest.raises(ValueError, match='cycle'):
        host().load([(Provider('a', dependencies=('b',), events=events), {}),
                     (Provider('b', dependencies=('a',), events=events), {})])
    with pytest.raises(ValueError, match='Duplicate'):
        host().load([(Provider('a', events=events), {}), (Provider('a', events=events), {})])
    assert events == []


def test_registration_precedes_start_and_close_reverses_once():
    events = []
    plugin_host = host()
    plugin_host.load([(Provider('a', events=events), {}),
                      (Provider('b', dependencies=('a',), events=events), {})])
    assert [event[:2] for event in events] == [('register', 'a'), ('register', 'b')]
    asyncio.run(plugin_host.start(object()))
    asyncio.run(plugin_host.close())
    asyncio.run(plugin_host.close())
    assert [event[:2] for event in events] == [
        ('register', 'a'), ('register', 'b'), ('start', 'a'), ('start', 'b'),
        ('close', 'b'), ('close', 'a')]


def test_start_failure_closes_already_started_plugins():
    events = []
    plugin_host = host()
    plugin_host.load([(Provider('a', events=events), {}),
                      (Provider('b', events=events, fail_start=True), {})])
    with pytest.raises(RuntimeError, match='startup failed'):
        asyncio.run(plugin_host.start(object()))
    assert [event[:2] for event in events][-4:] == [
        ('start', 'a'), ('start', 'b'), ('close', 'b'), ('close', 'a')]


def test_start_failure_closes_failing_provider_and_preserves_start_error():
    events = []
    class FailsAndCloses(Provider):
        async def close(self):
            await super().close()
            raise RuntimeError('cleanup failed')
    plugin_host = host()
    plugin_host.load([(Provider('a', events=events), {}),
                      (FailsAndCloses('b', events=events, fail_start=True), {})])
    with pytest.raises(RuntimeError, match='startup failed'):
        asyncio.run(plugin_host.start(object()))
    assert [event[:2] for event in events][-4:] == [
        ('start', 'a'), ('start', 'b'), ('close', 'b'), ('close', 'a')]


def test_local_module_is_imported_only_when_enabled(monkeypatch):
    from agent.plugins import host as host_module
    imports = []
    original_import = host_module.import_module
    def observed_import(name):
        imports.append(name)
        return original_import(name)
    monkeypatch.setattr(host_module, 'import_module', observed_import)
    module = ModuleType('test_local_plugin')
    module.plugin = Provider('local')
    monkeypatch.setitem(sys.modules, 'test_local_plugin', module)
    registry = build_default(Settings(), ScanGate('example.com', batch_mode=True, is_tty=False), 'example.com')
    assert 'test_local_plugin' not in imports
    assert 'test_local_plugin' not in registry.plugin_host.plugin_ids
    registry = build_default(Settings(plugins=[{'id': 'local', 'module': 'test_local_plugin'}]),
        ScanGate('example.com', batch_mode=True, is_tty=False), 'example.com')
    assert registry.plugin_host.plugin_ids[-1] == 'local'
    assert imports == ['test_local_plugin']


def test_registration_collision_rolls_back_all_tools():
    from agent.tools.builtin.dns_query import DNSQueryTool
    events = []
    class AddsTool(Provider):
        def describe_tool_names(self, validated_config):
            return ('dns_query',)
        def register(self, host, validated_config):
            super().register(host, validated_config)
            host.register_tool(DNSQueryTool(Settings()))
    plugin_host = host()
    with pytest.raises(ValueError, match='dns_query'):
        plugin_host.load([(AddsTool('first', events=events), {}),
                          (AddsTool('second', events=events), {})])
    assert plugin_host.registry.names() == []
    assert plugin_host.plugin_ids == ()
    assert events == []


def test_registration_must_match_declared_names():
    from agent.tools.builtin.dns_query import DNSQueryTool
    class Undeclared(Provider):
        def register(self, host, validated_config):
            host.register_tool(DNSQueryTool(Settings()))
    plugin_host = host()
    with pytest.raises(ValueError, match='undeclared'):
        plugin_host.load([(Undeclared('undisclosed'), {})])
    assert plugin_host.registry.names() == []


def test_direct_registry_registration_cannot_exceed_declaration():
    from agent.tools.builtin.dns_query import DNSQueryTool
    class BypassesHost(Provider):
        def register(self, host, validated_config):
            host.registry.register(DNSQueryTool(Settings()))
    plugin_host = host()
    with pytest.raises(ValueError, match='undeclared'):
        plugin_host.load([(BypassesHost('bypass'), {})])
    assert plugin_host.registry.names() == []


@pytest.mark.parametrize('inside_event_loop', [False, True])
def test_registration_failure_leaves_no_tools_or_active_work(inside_event_loop):
    events = []
    class DeclarativeProvider(Provider):
        def __init__(self, name, *, fail=False):
            super().__init__(name, events=events)
            self.fail = fail
        def describe_tool_names(self, validated_config): return (self.manifest.id + '_tool',)
        def register(self, host, validated_config):
            events.append(('register', self.manifest.id))
            host.register_tool(type('IdleTool', (), {'name': self.manifest.id + '_tool'})())
            if self.fail:
                raise RuntimeError('registration failed')
        async def start(self, session_view): events.append(('start', self.manifest.id))
    plugin_host = host()
    def load():
        with pytest.raises(RuntimeError, match='registration failed'):
            plugin_host.load([(DeclarativeProvider('first'), {}),
                              (DeclarativeProvider('second', fail=True), {})])
    if inside_event_loop:
        async def run():
            load()
            await asyncio.sleep(0)
        asyncio.run(run())
    else:
        load()
    assert events == [('register', 'first'), ('register', 'second')]
    assert plugin_host.registry.names() == []


def test_start_is_idempotent():
    events = []
    plugin_host = host()
    plugin_host.load([(Provider('one', events=events), {})])
    async def exercise():
        await plugin_host.start(object())
        await plugin_host.start(object())
        await plugin_host.close()
    asyncio.run(exercise())
    assert [event[0] for event in events].count('start') == 1


def test_concurrent_start_only_starts_provider_once():
    events = []
    class SlowProvider(Provider):
        async def start(self, session_view):
            events.append('start')
            await asyncio.sleep(0)
    plugin_host = host()
    plugin_host.load([(SlowProvider('slow'), {})])
    async def exercise():
        await asyncio.gather(plugin_host.start(object()), plugin_host.start(object()))
        await plugin_host.close()
    asyncio.run(exercise())
    assert events == ['start']


def test_registration_rejects_started_async_work():
    events = []
    class StartsWork(Provider):
        def register(self, host, validated_config):
            async def work():
                events.append('work ran')
            asyncio.create_task(work())
    async def exercise():
        plugin_host = host()
        with pytest.raises(ValueError, match='external work'):
            plugin_host.load([(StartsWork('bad'), {})])
        await asyncio.sleep(0)
        assert plugin_host.registry.names() == []
        assert events == []
    asyncio.run(exercise())


def test_explicit_entry_point_discovery_and_order(monkeypatch):
    from agent.plugins import host as host_module
    events = []
    class Entry:
        def __init__(self, name): self.name = name
        def load(self): return Provider(self.name, events=events)
    monkeypatch.setattr(host_module.metadata, 'entry_points',
        lambda **kwargs: [Entry('z'), Entry('a')])
    plugin_host = host()
    plugin_host.load_enabled(Settings(plugins=[{'id': 'z', 'entry_point': 'z'},
                                               {'id': 'a', 'entry_point': 'a'}]))
    assert plugin_host.plugin_ids == ('z', 'a')
    assert [e[1] for e in events] == ['z', 'a']


def test_explicit_file_path_is_loaded_only_when_enabled(tmp_path):
    plugin_file = tmp_path / 'local_plugin.py'
    plugin_file.write_text("from agent.plugins.api import PluginManifest\n"
        "class Local:\n"
        "    manifest = PluginManifest(id='from-file', version='1', api_version='1.0', capabilities=('tools',))\n"
        "    def describe_tool_names(self, validated_config): return ()\n"
        "    def register(self, host, validated_config): pass\n"
        "    async def start(self, session_view): pass\n"
        "    async def close(self): pass\n"
        "plugin = Local()\n", encoding='utf-8')
    plugin_host = host()
    plugin_host.load_enabled(Settings())
    assert plugin_host.plugin_ids == ()
    assert 'local_plugin' not in sys.modules
    enabled = host()
    enabled.load_enabled(Settings(plugins=[{'id': 'from-file', 'path': str(plugin_file)}]))
    assert enabled.plugin_ids == ('from-file',)


def test_registry_cleans_waiter_and_connectors_when_plugin_close_fails():
    events = []
    registry = host().registry
    class BadHost:
        async def close(self):
            events.append('plugin')
            raise RuntimeError('plugin cleanup failed')
    class Connector:
        async def aclose(self): events.append('connector')
    async def close_waiter(): events.append('waiter')
    registry.plugin_host = BadHost()
    registry.waiter.close = close_waiter
    registry._tools['connector'] = Connector()
    with pytest.raises(RuntimeError, match='plugin cleanup failed'):
        asyncio.run(registry.aclose())
    assert events == ['plugin', 'waiter', 'connector']


def test_mcp_bridge_starts_plugin_on_call_and_closes_it(monkeypatch):
    module = ModuleType('bridge_plugin')
    events = []
    module.plugin = Provider('bridge', events=events)
    monkeypatch.setitem(sys.modules, 'bridge_plugin', module)
    bridge = MCPBridge(Settings(plugins=[{'id': 'bridge', 'module': 'bridge_plugin'}]),
                       ['example.com'])
    assert any(item['name'] == 'dns_query' for item in bridge.tool_schemas())
    assert [event[0] for event in events] == ['register']
    async def exercise():
        await bridge.call('missing_tool', {'target': 'example.com'})
        await bridge.aclose()
    asyncio.run(exercise())
    assert [event[0] for event in events] == ['register', 'start', 'close']
