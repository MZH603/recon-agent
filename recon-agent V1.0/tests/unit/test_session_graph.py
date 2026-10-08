"""Offline contracts for the checkpointed session runtime."""
import asyncio
import importlib.util
from langgraph.errors import NodeCancelledError

from pydantic import BaseModel

from efficiency.budget_guard import BudgetGuard
from gate.scan_gate import ScanGate
from model.base import LLMResponse, NormalizedToolCall, ModelUnavailable
from tools.base import BaseTool, ToolResult
from tools.registry import ToolRegistry
from utils.config import Settings


def test_runtime_is_available():
    assert importlib.util.find_spec('core.orchestration') is not None


class Params(BaseModel):
    target: str


class FakeTool(BaseTool):
    name = 'fixture'
    description = 'offline fixture'
    params_model = Params

    def __init__(self, level=0, result=None):
        self.min_level = level
        self.calls = 0
        self.result = result or ToolResult(name=self.name, success=True, data={'hosts': ['fixture']},
                                         stdout='fixture output', evidence=['fixture://source'], source_hash='abc')

    async def run(self, params):
        self.calls += 1
        return self.result


class ScriptedLLM:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0
        self.messages = []
        self.guard = BudgetGuard()

    async def complete(self, messages, tools=None):
        self.messages.append(messages)
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        self.guard.register(response.token_usage.get('input', 0), response.token_usage.get('output', 0))
        return response


def response(name, arguments=None, identifier='call'):
    return LLMResponse(tool_calls=[NormalizedToolCall(id=identifier, name=name, arguments=arguments or {})])


def fixture(tmp_path, llm, level=0, settings=None, result=None, **kwargs):
    from core.orchestration import SessionRuntime
    settings = settings or Settings()
    gate = ScanGate('example.com', auth_dir=tmp_path / 'auth')
    registry = ToolRegistry(settings, gate, 'example.com')
    tool = FakeTool(level, result)
    registry.register(tool)
    runtime = SessionRuntime(target='example.com', registry=registry, llm=llm, gate=gate,
                             settings=settings, db_path=tmp_path / 'session.db', session_id='test', **kwargs)
    return runtime, tool, gate


def test_idle_startup_makes_no_calls(tmp_path):
    async def scenario():
        llm = ScriptedLLM()
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.state()
            assert state['status'] == 'idle' and state['session_id'] == 'test'
            assert llm.calls == tool.calls == 0
    asyncio.run(scenario())


def test_full_results_and_conversation_are_checkpointed(tmp_path):
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}),
                          response('finish_task', {'answer': 'Observed fixture', 'evidence': ['fixture://source']}))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.submit('Inspect fixture')
            assert state['status'] == 'completed'
            assert state['results'][0]['data'] == {'hosts': ['fixture']}
            assert state['results'][0]['source_hash'] == 'abc'
            assert llm.messages[1][1]['tool_calls'][0]['id'] == 'call'
            assert llm.messages[1][2]['role'] == 'tool'
        restored, _, _ = fixture(tmp_path, ScriptedLLM())
        async with restored:
            assert (await restored.state())['results'] == state['results']
        assert tool.calls == 1
    asyncio.run(scenario())


def test_l1_interrupt_and_resume_executes_only_after_yes(tmp_path):
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}), response('ask_user', {'question': 'Next?'}))
        runtime, tool, gate = fixture(tmp_path, llm, level=1)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'authorization' and tool.calls == 0
            state = await runtime.resume('yes')
            assert tool.calls == 1 and gate.current_level() == 1
            assert state['pending']['question'] == 'Next?'
    asyncio.run(scenario())


def test_restored_authorization_requires_fresh_confirmation(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'})), level=2)
        async with runtime:
            await runtime.submit('Inspect')
            state = await runtime.resume('CONFIRM 2')
            assert state['pending']['kind'] == 'authorization'
        restored, tool2, gate2 = fixture(tmp_path, ScriptedLLM(response('ask_user', {'question': 'Next?'})), level=2)
        async with restored:
            state = await restored.resume('example.com')
            assert 'CONFIRM 2' in state['pending']['question']
            assert tool2.calls == tool.calls == 0 and gate2.current_level() == 0
            for text in ('CONFIRM 2', 'example.com', 'I UNDERSTAND AND AUTHORIZE'):
                state = await restored.resume(text)
            assert tool2.calls == 0
            await restored.resume('yes')
            assert tool2.calls == 1
    asyncio.run(scenario())


def test_invalid_scope_is_checked_before_authorization(tmp_path):
    async def scenario():
        runtime, tool, gate = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'outside.net'})), level=2)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'validation'
            assert tool.calls == 0 and not gate.confirm_log
    asyncio.run(scenario())


def test_schema_correction_is_bounded(tmp_path):
    async def scenario():
        llm = ScriptedLLM(*(response('fixture', {}) for _ in range(3)))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'schema' and llm.calls == 3 and tool.calls == 0
            assert len([m for m in state['messages'] if m['role'] == 'tool']) == 3
    asyncio.run(scenario())


def test_duplicate_reuses_full_result_with_cache_flag(tmp_path):
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}),
                          response('fixture', {'target': 'example.com'}, 'other'),
                          response('ask_user', {'question': 'Next?'}))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert tool.calls == 1 and state['results'][1]['cached'] is True
            assert state['results'][1]['data'] == state['results'][0]['data']
            assert state['results'][1]['evidence'] == ['fixture://source']
    asyncio.run(scenario())


def test_plain_model_output_and_unsupported_finish_pause(tmp_path):
    async def scenario():
        for llm in (ScriptedLLM(LLMResponse(content='All secure')),
                    ScriptedLLM(response('finish_task', {'answer': 'All secure', 'evidence': ['invented']}))):
            runtime, tool, _ = fixture(tmp_path / str(id(llm)), llm)
            async with runtime:
                state = await runtime.submit('Inspect')
                assert state['status'] == 'paused' and state['answer'] == '' and tool.calls == 0
    asyncio.run(scenario())


def test_model_outage_and_failed_tool_pause(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path / 'outage', ScriptedLLM(ModelUnavailable('offline')))
        async with runtime:
            assert (await runtime.submit('Inspect'))['pending']['kind'] == 'model_unavailable'
        runtime, tool, _ = fixture(tmp_path / 'failed', ScriptedLLM(response('fixture', {'target': 'example.com'})),
                                  result=ToolResult.err('fixture', 'failed'))
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'tool_failure' and tool.calls == 1
    asyncio.run(scenario())


def test_budget_and_decision_limits_survive_restart(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(response('ask_user', {'question': 'Next?'})), max_decisions=1)
        async with runtime:
            await runtime.submit('Inspect')
        restored, _, _ = fixture(tmp_path, ScriptedLLM(), max_decisions=1)
        async with restored:
            state = await restored.resume('Continue')
            assert state['pending']['kind'] == 'limit' and state['decisions'] == 1
    asyncio.run(scenario())


def test_journal_uncertain_requires_explicit_retry_or_skip(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'}),
                                                        response('ask_user', {'question': 'Next?'})))
        async with runtime:
            await runtime.store.start('test', 'old', 'fixture', {'target': 'example.com'})
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'uncertain' and tool.calls == 0
            state = await runtime.resume('skip')
            assert tool.calls == 0 and state['pending']['kind'] == 'tool_failure'
    asyncio.run(scenario())


def test_xml_controls_and_sequential_queue(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(content='<tool_call><tool_name>update_plan</tool_name><parameters><plan>Observe fixture</plan></parameters></tool_call>'),
                          response('ask_user', {'question': 'Choose next', 'options': ['Inspect', 'Stop']}))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.submit('Plan')
            assert state['plan'] == 'Observe fixture' and tool.calls == 0
            assert state['pending']['options'] == ['Inspect', 'Stop']
    asyncio.run(scenario())


def test_real_queue_stops_at_action_limit_and_can_continue(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(tool_calls=[
            NormalizedToolCall(id='one', name='fixture', arguments={'target': 'a.example.com'}),
            NormalizedToolCall(id='two', name='fixture', arguments={'target': 'b.example.com'})]),
            response('ask_user', {'question': 'Next?'}))
        runtime, tool, _ = fixture(tmp_path, llm, max_actions=1)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert tool.calls == 1 and state['pending']['kind'] == 'limit'
            assert state['queued_calls'][0]['id'] == 'two'
            state = await runtime.resume('Continue')
            assert tool.calls == 2 and state['actions'] == 2
            assert state['results'][1]['target'] == 'b.example.com'
            assert state['results'][1]['arguments'] == {'target': 'b.example.com'}
            assert state['results'][1]['min_level'] == 0
            assert [m['tool_call_id'] for m in llm.messages[1] if m['role'] == 'tool'] == ['one', 'two']
            assert [m['role'] for m in llm.messages[1]][1:4] == ['assistant', 'tool', 'tool']
    asyncio.run(scenario())


def test_explicit_next_task_can_refresh_completed_results(tmp_path):
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}),
                          response('finish_task', {'answer': 'Observed fixture', 'evidence': ['fixture://source']}),
                          response('fixture', {'target': 'example.com'}), response('ask_user', {'question': 'Next?'}))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            first = await runtime.submit('Inspect')
            second = await runtime.submit('Refresh the observation')
            assert tool.calls == 2 and first['task_id'] != second['task_id']
    asyncio.run(scenario())


def test_cost_and_tokens_survive_restart_without_budget_reset(tmp_path):
    async def scenario():
        settings = Settings(MAX_TOKENS_PER_TASK=10, MAX_COST_PER_TASK=0.5)
        llm = ScriptedLLM(LLMResponse(tool_calls=[NormalizedToolCall(id='ask', name='ask_user', arguments={'question': 'Next?'})],
                                     token_usage={'input': 4, 'output': 3, 'cost': 0.5}))
        runtime, _, _ = fixture(tmp_path, llm, settings=settings)
        async with runtime:
            await runtime.submit('Inspect')
        restored, tool, _ = fixture(tmp_path, ScriptedLLM(), settings=settings)
        async with restored:
            state = await restored.resume('Continue')
            assert state['pending']['kind'] == 'budget'
            assert state['used_cost'] == 0.5 and state['used_tokens'] == 7 and tool.calls == 0
    asyncio.run(scenario())


def test_noninteractive_l2_is_blocked(tmp_path):
    async def scenario():
        for flags in ({'batch_mode': True}, {'is_tty': False}):
            runtime, tool, gate = fixture(tmp_path / next(iter(flags)), ScriptedLLM(response('fixture', {'target': 'example.com'})), level=2)
            for key, value in flags.items():
                setattr(gate, key, value)
            async with runtime:
                state = await runtime.submit('Inspect')
                assert state['pending']['kind'] == 'authorization_blocked' and tool.calls == 0
    asyncio.run(scenario())


def test_real_crash_started_checkpoint_rechecks_auth_and_stop_is_safe(tmp_path):
    class CrashTool(FakeTool):
        async def run(self, params):
            self.calls += 1
            raise asyncio.CancelledError()

    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'})), level=1)
        runtime.registry.register(CrashTool(level=1))
        async with runtime:
            await runtime.submit('Inspect')
            try:
                await runtime.resume('yes')
            except (asyncio.CancelledError, NodeCancelledError):
                pass
        restored, tool, gate = fixture(tmp_path, ScriptedLLM(), level=1)
        async with restored:
            state = await restored.state()
            assert state['pending']['kind'] == 'recovery'
            state = await restored.resume('Continue')
            assert state['pending']['kind'] == 'authorization' and gate.current_level() == 0
            state = await restored.resume('yes')
            assert state['pending']['kind'] == 'uncertain' and tool.calls == 0
        stopped, tool, gate = fixture(tmp_path, ScriptedLLM(), level=1)
        async with stopped:
            state = await stopped.resume('Stop')
            assert state['status'] == 'idle' and tool.calls == 0 and gate.current_level() == 0
    asyncio.run(scenario())


def test_completed_journal_survives_crash_before_checkpoint(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'})))
        async with runtime:
            commit = runtime.store.complete
            async def crash_after_commit(*args):
                await commit(*args)
                raise asyncio.CancelledError()
            runtime.store.complete = crash_after_commit
            try:
                await runtime.submit('Inspect')
            except (asyncio.CancelledError, NodeCancelledError):
                pass
            assert tool.calls == 1
        restored, second_tool, _ = fixture(tmp_path, ScriptedLLM(response('ask_user', {'question': 'Next?'})))
        async with restored:
            assert (await restored.state())['pending']['kind'] == 'recovery'
            state = await restored.resume('Continue')
            assert second_tool.calls == 0
            assert state['results'][0]['data'] == {'hosts': ['fixture']}
            assert state['results'][0]['evidence'] == ['fixture://source']
    asyncio.run(scenario())


def test_conflicting_version_evidence_pauses_and_keeps_both(tmp_path):
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}),
                          response('fixture', {'target': 'www.example.com'}, 'other'))
        runtime, tool, _ = fixture(tmp_path, llm)
        answers = [ToolResult(name='fixture', success=True, data={'host': 'example.com', 'tech': {'server': {'name': 'nginx', 'version': version}}}, evidence=[version])
                   for version in ('1.0', '2.0')]
        async def run(params):
            return answers.pop(0)
        tool.run = run
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'conflict'
            assert len(state['results']) == 2 and len(state['conflicts']) == 1
    asyncio.run(scenario())


def test_clarification_only_completion_marks_no_evidence(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(response('finish_task', {'answer': 'Task clarified', 'clarification_only': True})))
        async with runtime:
            state = await runtime.submit('Clarify the task without scanning')
            assert state['status'] == 'completed' and '[无证据]' in state['answer']
    asyncio.run(scenario())



def test_stop_api_persists_idle_without_external_calls(tmp_path):
    async def scenario():
        runtime, tool, gate = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'})), level=2)
        async with runtime:
            await runtime.submit('Inspect')
            state = await runtime.stop(abort=True)
            assert state['status'] == 'idle' and not state['pending'] and not state['queued_calls']
            assert gate.current_level() == 0 and tool.calls == 0
            assert state['messages'][-1]['role'] == 'tool'
    asyncio.run(scenario())


def test_l2_url_target_has_valid_signature_filename(tmp_path):
    async def scenario():
        gate = ScanGate('https://example.com:443/path', auth_dir=tmp_path)
        replies = iter(('CONFIRM 2', gate.target, 'I UNDERSTAND AND AUTHORIZE'))
        async def prompt(question):
            return next(replies)
        gate._prompt_fn = prompt
        for step in (1, 2, 3):
            assert (await gate.request_level_2_step(step))[0]
        assert gate.verify_signature() and gate.sig_path.parent == tmp_path
    asyncio.run(scenario())


def test_l2_exact_codes_must_be_confirmed_in_order(tmp_path):
    async def scenario():
        gate = ScanGate('example.com', auth_dir=tmp_path)
        async def prompt(question):
            return 'I UNDERSTAND AND AUTHORIZE'
        gate._prompt_fn = prompt
        granted, _ = await gate.request_level_2_step(3)
        assert not granted and gate.current_level() == 0
    asyncio.run(scenario())


def test_missing_resume_id_does_not_create_new_session(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(), require_existing=True)
        try:
            async with runtime:
                raise AssertionError('Missing session must not open')
        except ValueError as exc:
            assert 'session' in str(exc).lower()
    asyncio.run(scenario())


def test_unknown_started_outcome_still_pauses_for_new_task(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'}), response('ask_user', {'question': 'Next?'})))
        async with runtime:
            await runtime.store.start('test', 'old', 'fixture', {'target': 'example.com'}, task_id='previous-task')
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'uncertain' and tool.calls == 0
    asyncio.run(scenario())


def test_schema_failure_keeps_full_result_for_reports(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(*(response('fixture', {}) for _ in range(3))))
        async with runtime:
            state = await runtime.submit('Inspect')
            assert len(state['results']) == 3
            assert all(not result['success'] and result['error'] for result in state['results'])
    asyncio.run(scenario())


def test_signature_corruption_fails_closed(tmp_path):
    gate = ScanGate('example.com', auth_dir=tmp_path)
    gate.unlock_level_2()
    gate.sig_path.write_text('not json', encoding='utf-8')
    assert gate.verify_signature() is False



def test_new_task_resets_schema_correction_allowance(tmp_path):
    async def scenario():
        llm = ScriptedLLM(*(response('fixture', {}) for _ in range(6)))
        runtime, _, _ = fixture(tmp_path, llm)
        async with runtime:
            await runtime.submit('Inspect')
            await runtime.stop()
            state = await runtime.submit('Try a new task')
            assert llm.calls == 6 and state['pending']['kind'] == 'schema'
    asyncio.run(scenario())


def test_failure_replan_cancels_remaining_native_calls(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(tool_calls=[
            NormalizedToolCall(id='one', name='fixture', arguments={'target': 'a.example.com'}),
            NormalizedToolCall(id='two', name='fixture', arguments={'target': 'b.example.com'})]),
            response('ask_user', {'question': 'New focus?'}))
        runtime, tool, _ = fixture(tmp_path, llm, result=ToolResult.err('fixture', 'failed'))
        async with runtime:
            await runtime.submit('Inspect')
            state = await runtime.resume('Change focus to reviewing the evidence')
            assert tool.calls == 1 and state['pending']['kind'] == 'ask_user'
            assert [m['role'] for m in llm.messages[1]][1:5] == ['assistant', 'tool', 'tool', 'user']
    asyncio.run(scenario())


def test_xml_declared_arrays_are_decoded_for_controls(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path / 'finish', ScriptedLLM(
            response('fixture', {'target': 'example.com'}),
            LLMResponse(content='<tool_call><tool_name>finish_task</tool_name><parameters><answer>Observed fixture</answer><evidence>["fixture://source"]</evidence></parameters></tool_call>')))
        async with runtime:
            assert (await runtime.submit('Inspect'))['status'] == 'completed'
        runtime, _, _ = fixture(tmp_path / 'ask', ScriptedLLM(
            LLMResponse(content='<tool_call><tool_name>ask_user</tool_name><parameters><question>Next?</question><options>["Inspect", "Stop"]</options></parameters></tool_call>')))
        async with runtime:
            assert (await runtime.submit('Inspect'))['pending']['options'] == ['Inspect', 'Stop']
    asyncio.run(scenario())


def test_model_error_history_survives_continue_and_restart(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(ModelUnavailable('outage-marker'), response('ask_user', {'question': 'Next?'})))
        async with runtime:
            await runtime.submit('Inspect')
            state = await runtime.resume('Continue')
            assert any('outage-marker' in event['question'] for event in state['events'])
        restored, _, _ = fixture(tmp_path, ScriptedLLM())
        async with restored:
            assert any('outage-marker' in event['question'] for event in (await restored.state())['events'])
    asyncio.run(scenario())


def test_started_journal_is_exported_for_partial_reports(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM())
        async with runtime:
            await runtime.store.start('test', 'partial', 'fixture', {'target': 'example.com'}, task_id='task')
            state = await runtime.state()
            assert state['executions'][0]['status'] == 'uncertain'
            assert state['executions'][0]['target'] == 'example.com'
            assert state['executions'][0]['arguments'] == {'target': 'example.com'}
            assert state['executions'][0]['execution_id'] == 'partial'
    asyncio.run(scenario())


def test_uncertain_invalid_reply_then_skip_resolves_journal(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'})))
        async with runtime:
            await runtime.store.start('test', 'old', 'fixture', {'target': 'example.com'})
            await runtime.submit('Inspect')
            state = await runtime.resume('what?')
            assert state['pending']['kind'] == 'uncertain'
            state = await runtime.resume('skip')
            assert state['pending']['kind'] == 'tool_failure' and tool.calls == 0
            assert state['executions'][0]['status'] == 'completed'
            assert 'skipped' in state['executions'][0]['result']['error']
    asyncio.run(scenario())


def test_uncertain_invalid_reply_then_retry_executes_once(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'}), response('ask_user', {'question': 'Next?'})))
        async with runtime:
            await runtime.store.start('test', 'old', 'fixture', {'target': 'example.com'})
            await runtime.submit('Inspect')
            await runtime.resume('what?')
            state = await runtime.resume('retry')
            assert tool.calls == 1 and state['pending']['kind'] == 'ask_user'
            assert len(state['executions']) == 2
            assert all(item['status'] == 'completed' for item in state['executions'])
    asyncio.run(scenario())
