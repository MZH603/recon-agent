"""Loop proposals cross the real graph and retain its safety nodes."""
import asyncio
import sys
from types import ModuleType

import pytest

from agent.core.orchestration.graph import SessionRuntime
from agent.efficiency.budget_guard import BudgetGuard
from agent.gate.scan_gate import ScanGate
from agent.model.base import LLMResponse, NormalizedToolCall
from agent.plugins.api import PluginManifest
from agent.plugins.loop import LoopView, ModelTurn, ToolBatch, Continue, AskUser
from agent.plugins.react_loop import ReactLoop
from agent.tools.registry import build_default
from agent.tools.base import ToolResult
from agent.utils.config import Settings


class Model:
    def __init__(self, responses):
        self.guard = BudgetGuard()
        self.responses = list(responses)
        self.requests = []

    def count_tokens(self, value):
        return max(1, len(value) // 4)

    async def complete(self, messages, tools):
        self.requests.append((messages, tools))
        response = self.responses.pop(0)
        response.token_usage = {'input': 10, 'output': 5, 'cost': 0.01}
        return response


def make_runtime(tmp_path, settings, responses, session_id='s', resume=False):
    gate = ScanGate('example.com', batch_mode=True, is_tty=False)
    registry = build_default(settings, gate, 'example.com')
    model = Model(responses)
    runtime = SessionRuntime(target='example.com', registry=registry, llm=model, gate=gate,
        settings=settings, db_path=tmp_path / 'session.sqlite', session_id=session_id,
        system_prompt='Host policy', require_existing=resume)
    return runtime, model


def test_default_react_cycles_model_tool_model_and_journals(tmp_path):
    responses = [LLMResponse(tool_calls=[NormalizedToolCall(id='a', name='dns_query',
        arguments={'target': 'outside.example.org', 'record_type': 'A'})]),
        LLMResponse(content='Done\n<task_complete/>')]
    runtime, model = make_runtime(tmp_path, Settings(), responses)
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'paused'
            assert state['pending']['kind'] == 'validation'
            state = await runtime.resume('Continue')
            assert state['status'] == 'completed'
            assert len(model.requests) == 2
            assert state['decisions'] == 2
            assert any('Scope rejection' in str(result) for result in state['results'])
            assert state['executions'] == []
    asyncio.run(run())


def test_plan_first_strategy_survives_resume(tmp_path):
    settings = Settings(agent_loop='builtin-plan-first')
    runtime, model = make_runtime(tmp_path, settings, [
        LLMResponse(content='I should plan'), LLMResponse(content='Done\n<task_complete/>')])
    async def first():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'completed'
            assert len(model.requests) == 2
            assert any('plan' in str(message).lower() for message in model.requests[0][0])
            assert state['loop_state']['builtin-plan-first'] == {'planned': True}
            assert state['context_cursor'] <= len(state['messages'])
    asyncio.run(first())
    resumed, _ = make_runtime(tmp_path, settings, [], resume=True)
    async def second():
        async with resumed:
            state = await resumed.state()
            assert state['loop_state']['builtin-plan-first'] == {'planned': True}
    asyncio.run(second())


def test_plan_first_rejects_native_tool_calls_until_plan_exists(tmp_path):
    runtime, model = make_runtime(tmp_path, Settings(agent_loop='builtin-plan-first'), [
        LLMResponse(tool_calls=[NormalizedToolCall(id='early', name='tool_catalog',
            arguments={'target': 'example.com'})])])
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
            assert not state['executions']
            assert not any(message.get('tool_calls') for message in state['messages'])
            assert len(model.requests) == 1
    asyncio.run(run())


def test_plan_first_rejects_xml_tool_calls_until_plan_exists(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(agent_loop='builtin-plan-first'), [
        LLMResponse(content='<tool_call><tool_name>tool_catalog</tool_name>'
                            '<parameters><target>example.com</target></parameters></tool_call>')])
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
            assert state['executions'] == []
    asyncio.run(run())


@pytest.mark.parametrize('loop_id', ['builtin-react', 'builtin-plan-first'])
def test_each_loop_uses_same_tool_journal_and_can_be_stopped(tmp_path, loop_id):
    responses = [LLMResponse(content='Plan ready')] if loop_id == 'builtin-plan-first' else []
    responses += [LLMResponse(tool_calls=[NormalizedToolCall(id='catalog-1', name='tool_catalog',
        arguments={'target': 'example.com', 'query': 'dns'})]),
        LLMResponse(content='Finished\n<task_complete/>')]
    runtime, model = make_runtime(tmp_path, Settings(agent_loop=loop_id), responses)
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'completed'
            assert len(state['executions']) == 1
            assert state['executions'][0]['status'] == 'completed'
            assert state['results'][0]['name'] == 'tool_catalog'
            assert state['used_cost'] >= .02
            stopped = await runtime.stop()
            assert stopped['status'] == 'stopped'
            assert len(stopped['executions']) == 1
    asyncio.run(run())


def test_loop_exception_pauses_without_fallback_or_second_model_call(tmp_path, monkeypatch):
    class BrokenLoop:
        manifest = PluginManifest(id='broken-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def register(self, host, config): pass
        async def start(self, view):
            assert isinstance(view, LoopView)
            assert not hasattr(view, 'registry')
        async def close(self): pass
        def prepare(self, view, state): return ModelTurn()
        def on_response(self, view, response, state): raise RuntimeError('strategy failed')
        def on_result(self, view, result, state): return state
        def on_event(self, view, event, state): pass
    module = ModuleType('test_broken_loop')
    module.plugin = BrokenLoop()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='broken-loop', plugins=[{'id': 'broken-loop', 'module': module.__name__}])
    runtime, model = make_runtime(tmp_path, settings, [LLMResponse(content='Done\n<task_complete/>')])
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'paused'
            assert state['pending']['kind'] == 'agent_loop'
            assert 'broken-loop' in state['pending']['question']
            assert len(model.requests) == 1
            assert state['decisions'] == 1
            assert state['used_cost'] >= .01
            stopped = await runtime.stop()
            assert stopped['status'] == 'stopped'
    asyncio.run(run())


def test_loop_cannot_discard_native_tool_replies(tmp_path, monkeypatch):
    class DiscardingLoop:
        manifest = PluginManifest(id='discarding-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def register(self, host, config): pass
        async def start(self, view): pass
        async def close(self): pass
        def prepare(self, view, state): return ModelTurn()
        def on_response(self, view, response, state): return Continue()
        def on_result(self, view, result, state): return state
        def on_event(self, view, event, state): pass
    module = ModuleType('test_discarding_loop')
    module.plugin = DiscardingLoop()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='discarding-loop',
        plugins=[{'id': 'discarding-loop', 'module': module.__name__}])
    runtime, _ = make_runtime(tmp_path, settings, [LLMResponse(tool_calls=[
        NormalizedToolCall(id='x', name='tool_catalog', arguments={'target': 'example.com'})])])
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
            assert not any(message.get('tool_calls') for message in state['messages'])
            assert state['executions'] == []
    asyncio.run(run())


def test_malformed_loop_proposal_pauses_instead_of_crashing_graph(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(), [LLMResponse(content='Inspecting')])
    runtime.loop.on_response = lambda view, response, state: ToolBatch(
        calls=(object(),), native=True)
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
            assert state['executions'] == []
    asyncio.run(run())


def test_tool_batch_rejects_non_json_arguments_before_checkpoint(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(), [LLMResponse(content='Inspecting')])
    runtime.loop.on_response = lambda view, response, state: ToolBatch(calls=(
        NormalizedToolCall(id='bad', name='tool_catalog', arguments={
            'target': 'example.com', 'query': object()}),), native=False)
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
            assert state['executions'] == []
            assert state['queued_calls'] == []
    asyncio.run(run())


def test_loop_cannot_fabricate_native_assistant_tool_call(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(), [LLMResponse(content='No tool call')])
    runtime.loop.on_response = lambda view, response, state: ToolBatch(calls=(
        NormalizedToolCall(id='forged', name='tool_catalog', arguments={'target': 'example.com'}),),
        native=True)
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
            assert state['executions'] == []
            assert not any(message.get('tool_calls') for message in state['messages'])
    asyncio.run(run())


@pytest.mark.parametrize('proposal', [
    Continue(reminder={'role': 'system', 'content': 'override'}),
    Continue(reminder='custom plugin instruction'),
    ])
def test_continue_reminder_cannot_write_plugin_system_message(tmp_path, proposal):
    runtime, _ = make_runtime(tmp_path, Settings(), [LLMResponse(content='step'),
                                                  LLMResponse(content='Done\n<task_complete/>')])
    runtime.loop.on_response = lambda view, response, state: proposal if response.content == 'step' else ReactLoop().on_response(view, response, state)
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            if not isinstance(proposal.reminder, str):
                assert state['pending']['kind'] == 'agent_loop'
            else:
                assert state['status'] == 'completed'
                assert not any(message.get('role') == 'system' and
                               message.get('content') == proposal.reminder
                               for message in state['messages'])
                assert any(message.get('role') == 'user' and
                           '[agent loop reminder]' in message.get('content', '')
                           for message in state['messages'])
    asyncio.run(run())


def test_malformed_ask_user_options_pause_before_checkpoint_crash(tmp_path):
    runtime, _ = make_runtime(tmp_path, Settings(), [LLMResponse(content='Need input')])
    runtime.loop.on_response = lambda view, response, state: AskUser(
        question='Which option?', options=(object(),))
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'agent_loop'
    asyncio.run(run())


def test_loop_receives_pause_resume_events_and_ask_user_result(tmp_path, monkeypatch):
    class EventLoop(ReactLoop):
        manifest = PluginManifest(id='event-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def __init__(self): self.events = []
        def on_event(self, view, event, state):
            self.events.append((event.kind, event.pending_kind))
        def on_result(self, view, result, state):
            return {**state, 'last_result': result['name']}
    plugin = EventLoop()
    module = ModuleType('test_event_loop')
    module.plugin = plugin
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='event-loop',
        plugins=[{'id': 'event-loop', 'module': module.__name__}])
    runtime, _ = make_runtime(tmp_path, settings, [
        LLMResponse(tool_calls=[NormalizedToolCall(id='ask', name='ask_user',
            arguments={'question': 'Proceed?', 'options': ['Yes', 'No']})]),
        LLMResponse(content='Done\n<task_complete/>')])
    async def run():
        async with runtime:
            paused = await runtime.submit('Inspect')
            assert paused['pending']['kind'] == 'ask_user'
            completed = await runtime.resume('Yes')
            assert completed['status'] == 'completed'
            assert completed['loop_state']['event-loop']['last_result'] == 'ask_user'
            assert ('pause', 'ask_user') in plugin.events
            assert ('resume', 'ask_user') in plugin.events
    asyncio.run(run())


def test_pause_event_state_is_durable_and_not_replayed_on_restart(tmp_path, monkeypatch):
    class DurableEventLoop(ReactLoop):
        manifest = PluginManifest(id='durable-event-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def __init__(self): self.observed = []
        def on_event(self, view, event, state):
            self.observed.append((event.kind, event.event_id))
            return {**state, 'events': state.get('events', []) + [[event.kind, event.event_id]]}
    module = ModuleType('test_durable_event_loop')
    first_plugin = DurableEventLoop()
    module.plugin = first_plugin
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='durable-event-loop',
        plugins=[{'id': 'durable-event-loop', 'module': module.__name__}])
    first, _ = make_runtime(tmp_path, settings, [LLMResponse(tool_calls=[
        NormalizedToolCall(id='ask', name='ask_user',
            arguments={'question': 'Proceed?', 'options': ['Yes']})])])
    async def pause():
        async with first:
            state = await first.submit('Inspect')
            assert state['pending']['kind'] == 'ask_user'
            assert state['loop_state']['durable-event-loop']['events'] == [
                ['pause', state['pending']['event_id']]]
    asyncio.run(pause())
    assert len(first_plugin.observed) == 1
    resumed_plugin = DurableEventLoop()
    module.plugin = resumed_plugin
    second, _ = make_runtime(tmp_path, settings,
        [LLMResponse(content='Done\n<task_complete/>')], resume=True)
    async def resume():
        async with second:
            state = await second.resume('Yes')
            assert state['status'] == 'completed'
            assert state['loop_state']['durable-event-loop']['events'] == [
                ['pause', first_plugin.observed[0][1]],
                ['resume', first_plugin.observed[0][1]]]
    asyncio.run(resume())
    assert resumed_plugin.observed == [('resume', first_plugin.observed[0][1])]


def test_update_plan_control_result_reaches_loop_hook(tmp_path, monkeypatch):
    class PlanTrackingLoop(ReactLoop):
        manifest = PluginManifest(id='plan-tracking-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def on_result(self, view, result, state):
            return {**state, 'last_result': result['name']}
    module = ModuleType('test_plan_tracking_loop')
    module.plugin = PlanTrackingLoop()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='plan-tracking-loop',
        plugins=[{'id': 'plan-tracking-loop', 'module': module.__name__}])
    runtime, _ = make_runtime(tmp_path, settings, [
        LLMResponse(tool_calls=[NormalizedToolCall(id='plan', name='update_plan',
            arguments={'plan': 'Inspect DNS'})]),
        LLMResponse(content='Done\n<task_complete/>')])
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'completed'
            assert state['loop_state']['plan-tracking-loop']['last_result'] == 'update_plan'
    asyncio.run(run())


def test_result_hook_failure_keeps_completed_journal_and_pauses(tmp_path, monkeypatch):
    class BrokenResultLoop(ReactLoop):
        manifest = PluginManifest(id='result-error-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def on_result(self, view, result, state):
            raise RuntimeError('result handler failed')
    module = ModuleType('test_result_error_loop')
    module.plugin = BrokenResultLoop()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='result-error-loop',
        plugins=[{'id': 'result-error-loop', 'module': module.__name__}])
    runtime, model = make_runtime(tmp_path, settings, [LLMResponse(tool_calls=[
        NormalizedToolCall(id='x', name='tool_catalog', arguments={'target': 'example.com'})])])
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'paused'
            assert state['pending']['kind'] == 'agent_loop'
            assert len(state['executions']) == 1
            assert state['executions'][0]['status'] == 'completed'
            assert len(state['results']) == 1
            assert len(model.requests) == 1
    asyncio.run(run())


def test_resume_rejects_a_different_loop(tmp_path):
    first, _ = make_runtime(tmp_path, Settings(), [])
    async def create():
        async with first:
            assert (await first.state())['loop_id'] == 'builtin-react'
    asyncio.run(create())
    second, _ = make_runtime(tmp_path, Settings(agent_loop='builtin-plan-first'), [], resume=True)
    async def reopen():
        with pytest.raises(ValueError, match='Stored agent loop'):
            async with second:
                pass
    asyncio.run(reopen())


@pytest.mark.parametrize('loop_id', ['builtin-react', 'builtin-plan-first'])
def test_uncertain_journal_requires_operator_choice_for_each_loop(tmp_path, loop_id):
    settings = Settings(agent_loop=loop_id)
    responses = [LLMResponse(content='Plan ready')] if loop_id == 'builtin-plan-first' else []
    responses += [LLMResponse(content='Done\n<task_complete/>')]
    runtime, model = make_runtime(tmp_path, settings, responses)
    async def run():
        async with runtime:
            before = await runtime.state()
            arguments = {'target': 'example.com', 'query': '', 'select': [], 'limit': 20}
            await runtime.store.start('s', 'uncertain-1', 'tool_catalog', arguments,
                                      before['task_id'])
            call = {'id': 'call-1', 'name': 'tool_catalog', 'arguments': arguments,
                    'native': False, 'execution_id': 'uncertain-1'}
            await runtime.graph.aupdate_state(runtime.config,
                {'queued_calls': [call], 'route': 'validate', 'status': 'running'},
                as_node='decide')
            await runtime.graph.ainvoke(None, runtime.config)
            paused = await runtime.state()
            assert paused['status'] == 'paused'
            assert paused['pending']['kind'] == 'uncertain'
            assert len(model.requests) == 0
            completed = await runtime.resume('skip')
            assert completed['status'] == 'completed'
            assert len(completed['executions']) == 1
            assert completed['executions'][0]['status'] == 'uncertain'
            assert any('skipped' in str(result) for result in completed['results'])
    asyncio.run(run())


@pytest.mark.parametrize('loop_id', ['builtin-react', 'builtin-plan-first'])
def test_completed_journal_replays_without_tool_execution(tmp_path, loop_id):
    settings = Settings(agent_loop=loop_id)
    responses = [LLMResponse(content='Plan ready')] if loop_id == 'builtin-plan-first' else []
    responses += [LLMResponse(content='Done\n<task_complete/>')]
    runtime, _ = make_runtime(tmp_path, settings, responses)
    async def run():
        async with runtime:
            before = await runtime.state()
            arguments = {'target': 'example.com', 'query': '', 'select': [], 'limit': 20}
            await runtime.store.start('s', 'completed-1', 'tool_catalog', arguments,
                                      before['task_id'])
            await runtime.store.complete('s', 'completed-1',
                ToolResult(name='tool_catalog', success=True,
                           data={'tools': [], 'selected_tools': []}).model_dump(mode='json'))
            call = {'id': 'call-1', 'name': 'tool_catalog', 'arguments': arguments,
                    'native': False, 'execution_id': 'completed-1'}
            await runtime.graph.aupdate_state(runtime.config,
                {'queued_calls': [call], 'route': 'validate', 'status': 'running'},
                as_node='decide')
            state = await runtime.graph.ainvoke(None, runtime.config)
            final = await runtime.state()
            assert final['status'] == 'completed'
            assert len(final['executions']) == 1
            assert final['results'][0]['name'] == 'tool_catalog'
            assert not final['results'][0].get('execution_id') or final['results'][0]['execution_id'] == 'completed-1'
    asyncio.run(run())


def test_model_continuation_limit_resets_with_bounded_segments(tmp_path):
    runtime, model = make_runtime(tmp_path, Settings(), [
        LLMResponse(content='Still inspecting'),
        LLMResponse(content='One more check'),
        LLMResponse(content='Done\n<task_complete/>')])
    runtime.max_decisions = 1
    runtime.max_steps = 1
    async def run():
        async with runtime:
            first = await runtime.submit('Inspect')
            assert first['pending']['kind'] == 'limit'
            second = await runtime.resume('Continue')
            assert second['pending']['kind'] == 'limit'
            assert 'Decision limit' in second['pending']['question']
            third = await runtime.resume('Continue')
            assert third['status'] == 'completed'
            assert len(model.requests) == 3
    asyncio.run(run())


def test_unknown_loop_fails_before_runtime_start(tmp_path):
    with pytest.raises(ValueError, match='loop'):
        make_runtime(tmp_path, Settings(agent_loop='missing'), [])


def test_loop_cannot_bypass_validation_and_error_pauses(tmp_path, monkeypatch):
    class UnsafeLoop:
        manifest = PluginManifest(id='unsafe-loop', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        def register(self, host, config): pass
        async def start(self, view): pass
        async def close(self): pass
        def prepare(self, view, state): return ModelTurn()
        def on_response(self, view, response, state):
            return ToolBatch(calls=(NormalizedToolCall(id='x', name='dns_query',
                arguments={'target': 'outside.example.org', 'record_type': 'A'}),))
        def on_result(self, view, result, state): return state
        def on_event(self, view, event, state): pass
    module = ModuleType('test_unsafe_loop')
    module.plugin = UnsafeLoop()
    monkeypatch.setitem(sys.modules, module.__name__, module)
    settings = Settings(agent_loop='unsafe-loop', plugins=[{'id': 'unsafe-loop', 'module': module.__name__}])
    runtime, model = make_runtime(tmp_path, settings, [LLMResponse(content='')], session_id='unsafe')
    async def run():
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'paused' or state['results']
            assert any('Scope rejection' in str(result) for result in state['results'])
            assert state['executions'] == []
    asyncio.run(run())
