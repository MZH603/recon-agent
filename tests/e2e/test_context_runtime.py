"""Context plugins go through the real session preview and decision path."""
import asyncio
import sys
from types import ModuleType

import pytest

from agent.core.orchestration.graph import SessionRuntime
from agent.efficiency.budget_guard import BudgetGuard
from agent.gate.scan_gate import ScanGate
from agent.model.base import LLMResponse
from agent.plugins.api import PluginManifest
from agent.plugins.context import ContextBlock
from agent.tools.registry import build_default
from agent.utils.config import Settings


class Provider:
    manifest = PluginManifest(id='sample-context', version='1.0', api_version='1.0',
                              capabilities=('context',))
    required = False

    def register(self, host, config): pass
    async def start(self, view): pass
    async def close(self): pass
    def collect(self, view):
        return [ContextBlock(id='note', source=self.manifest.id, trust='external',
                             priority=1, content='source note', required=False)]


class Model:
    def __init__(self):
        self.guard = BudgetGuard()
        self.requests = []

    def count_tokens(self, payload):
        return max(1, len(payload) // 4)

    async def complete(self, messages, tools):
        self.requests.append(messages)
        return LLMResponse(content='Done\n<task_complete/>', token_usage={'input': 10, 'output': 5, 'cost': 0.0})


def runtime(tmp_path, settings):
    gate = ScanGate('example.com', batch_mode=True, is_tty=False)
    registry = build_default(settings, gate, 'example.com')
    model = Model()
    return SessionRuntime(target='example.com', registry=registry, llm=model, gate=gate,
                          settings=settings, db_path=tmp_path / 'session.sqlite',
                          session_id='s', system_prompt='Host policy'), model


def test_preview_and_model_receive_same_provider_context(tmp_path, monkeypatch):
    module = ModuleType('sample_context_plugin')
    module.plugin = Provider()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(plugins=[{'id': 'sample-context', 'module': module.__name__}])
    session, model = runtime(tmp_path, settings)
    async def run():
        async with session:
            preview = await session.state()
            assert preview['context_tokens'] > 0
            result = await session.submit('Inspect')
            assert result['status'] == 'completed'
            assert model.requests
            assert any('source note' in message['content'] for message in model.requests[0])
    asyncio.run(run())


def test_required_provider_failure_pauses_before_model_call(tmp_path, monkeypatch):
    class Broken(Provider):
        required = True
        def collect(self, view):
            raise RuntimeError('index unavailable')
    module = ModuleType('broken_context_plugin')
    module.plugin = Broken()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(plugins=[{'id': 'sample-context', 'module': module.__name__}])
    session, model = runtime(tmp_path, settings)
    async def run():
        async with session:
            result = await session.submit('Inspect')
            assert result['status'] == 'paused'
            assert result['pending']['kind'] == 'context_provider'
            assert 'sample-context' in result['pending']['question']
            assert not model.requests
    asyncio.run(run())


def test_optional_provider_failure_records_event_and_model_continues(tmp_path, monkeypatch):
    class Broken(Provider):
        def collect(self, view):
            raise RuntimeError('optional index unavailable')
    module = ModuleType('optional_context_plugin')
    module.plugin = Broken()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(plugins=[{'id': 'sample-context', 'module': module.__name__}])
    session, model = runtime(tmp_path, settings)
    async def run():
        async with session:
            result = await session.submit('Inspect')
            assert result['status'] == 'completed'
            assert model.requests
            assert any(event.get('kind') == 'context_provider_error' and
                       event.get('provider') == 'sample-context' for event in result['events'])
    asyncio.run(run())
