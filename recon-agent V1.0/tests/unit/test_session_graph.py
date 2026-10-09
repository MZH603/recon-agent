"""Offline contracts for the checkpointed session runtime."""
import asyncio
from langgraph.errors import NodeCancelledError

from pydantic import BaseModel

from efficiency.budget_guard import BudgetGuard
from gate.scan_gate import ScanGate
from model.base import LLMResponse, NormalizedToolCall, ModelUnavailable
from tools.base import BaseTool, ToolResult
from tools.registry import ToolRegistry
from utils.config import Settings


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
                          LLMResponse(content='Observed fixture\n<task_complete/>'))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.submit('Inspect fixture')
            assert state['status'] == 'completed'
            assert state['results'][0]['data'] == {'hosts': ['fixture']}
            assert state['results'][0]['source_hash'] == 'abc'
            batch = [m for m in llm.messages[1] if m['role'] != 'system']
            assert batch[1]['tool_calls'][0]['id'] == 'call'
            assert batch[2]['role'] == 'tool'
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


def test_plain_output_continues_and_old_finish_is_not_model_visible(tmp_path):
    from core.orchestration.controls import control_specs
    assert 'finish_task' not in {spec['function']['name'] for spec in control_specs()}
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(LLMResponse(content='Working'),
                                  LLMResponse(content='Answer\n<task_complete/>')))
        async with runtime:
            state = await runtime.submit('Explain')
            assert state['status'] == 'completed' and tool.calls == 0
    asyncio.run(scenario())


def test_model_outage_and_failed_tool_pause(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path / 'outage', ScriptedLLM(ModelUnavailable('offline')))
        async with runtime:
            assert (await runtime.submit('Inspect'))['pending']['kind'] == 'model_unavailable'
        runtime, tool, _ = fixture(tmp_path / 'failed', ScriptedLLM(response('fixture', {'target': 'example.com'}), LLMResponse(content='Failure explained\n<task_complete/>')),
                                  result=ToolResult.err('fixture', 'failed'))
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'completed' and tool.calls == 1
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
            assert tool.calls == 0 and state['pending']['kind'] == 'ask_user'
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
            assert [m['role'] for m in llm.messages[1] if m['role'] != 'system'][1:4] == ['assistant', 'tool', 'tool']
    asyncio.run(scenario())


def test_explicit_next_task_can_refresh_completed_results(tmp_path):
    async def scenario():
        llm = ScriptedLLM(response('fixture', {'target': 'example.com'}),
                          LLMResponse(content='Observed fixture\n<task_complete/>'),
                          response('fixture', {'target': 'example.com'}), response('ask_user', {'question': 'Next?'}))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            first = await runtime.submit('Inspect')
            await runtime.new_task()
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
            assert state['status'] == 'stopped' and tool.calls == 0 and gate.current_level() == 0
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
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(LLMResponse(content='Task clarified\n<task_complete/>')))
        async with runtime:
            state = await runtime.submit('Clarify the task without scanning')
            assert state['status'] == 'completed' and state['answer'] == 'Task clarified'
    asyncio.run(scenario())



def test_stop_api_persists_stopped_without_external_calls(tmp_path):
    async def scenario():
        runtime, tool, gate = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'})), level=2)
        async with runtime:
            await runtime.submit('Inspect')
            state = await runtime.stop(abort=True)
            assert state['status'] == 'stopped' and not state['pending'] and not state['queued_calls']
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


def test_failure_returns_model_after_native_batch(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(tool_calls=[
            NormalizedToolCall(id='one', name='fixture', arguments={'target': 'a.example.com'}),
            NormalizedToolCall(id='two', name='fixture', arguments={'target': 'b.example.com'})]),
            response('ask_user', {'question': 'New focus?'}))
        runtime, tool, _ = fixture(tmp_path, llm, result=ToolResult.err('fixture', 'failed'))
        async with runtime:
            state = await runtime.submit('Inspect')
            assert tool.calls == 2 and state['pending']['kind'] == 'ask_user'
            assert [m['role'] for m in llm.messages[1] if m['role'] != 'system'][1:4] == ['assistant', 'tool', 'tool']
    asyncio.run(scenario())


def test_xml_declared_arrays_are_decoded_for_controls(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path / 'finish', ScriptedLLM(
            response('fixture', {'target': 'example.com'}),
            LLMResponse(content='Observed fixture\n<task_complete/>')))
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


def test_uncertain_invalid_reply_then_skip_preserves_unknown_journal(tmp_path):
    async def scenario():
        runtime, tool, _ = fixture(tmp_path, ScriptedLLM(response('fixture', {'target': 'example.com'}), response('ask_user', {'question': 'Next?'})))
        async with runtime:
            await runtime.store.start('test', 'old', 'fixture', {'target': 'example.com'})
            await runtime.submit('Inspect')
            state = await runtime.resume('what?')
            assert state['pending']['kind'] == 'uncertain'
            state = await runtime.resume('skip')
            assert state['pending']['kind'] == 'ask_user' and tool.calls == 0
            assert state['executions'][0]['status'] == 'uncertain'
            previous = await runtime.store.lookup('test', 'later', 'fixture', {'target':'example.com'})
            assert previous['status'] == 'started'
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
            assert state['executions'][0]['status'] == 'uncertain'
            assert state['executions'][1]['status'] == 'completed'
    asyncio.run(scenario())


def test_active_session_rejects_second_runtime_owner(tmp_path):
    async def scenario():
        first, _, _ = fixture(tmp_path, ScriptedLLM())
        second, _, _ = fixture(tmp_path, ScriptedLLM())
        async with first:
            try:
                async with second:
                    raise AssertionError('Second owner must be rejected')
            except ValueError as exc:
                assert 'active' in str(exc).lower() or 'already' in str(exc).lower()
            assert (await first.state())['status'] == 'idle'
        async with second:
            assert (await second.state())['status'] == 'idle'
    asyncio.run(scenario())


def test_process_owner_blocks_duplicate_and_crash_releases(tmp_path):
    import subprocess
    import sys

    child_code = '''
import asyncio, sys
from pathlib import Path
from core.orchestration import SessionRuntime
from gate.scan_gate import ScanGate
from tools.registry import ToolRegistry
from utils.config import Settings
async def main():
    settings = Settings()
    path = Path(sys.argv[1])
    gate = ScanGate('example.com', auth_dir=path.parent / 'auth')
    registry = ToolRegistry(settings, gate, 'example.com')
    async with SessionRuntime(target='example.com', registry=registry, llm=object(), gate=gate,
                              settings=settings, db_path=path, session_id='test'):
        print('READY', flush=True)
        await asyncio.to_thread(sys.stdin.readline)
asyncio.run(main())
'''
    child = subprocess.Popen([sys.executable, '-c', child_code, str(tmp_path / 'session.db')],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'READY'
        async def blocked():
            runtime, _, _ = fixture(tmp_path, ScriptedLLM())
            try:
                async with runtime:
                    raise AssertionError('Cross-process owner must be rejected')
            except ValueError as exc:
                assert 'active' in str(exc).lower() or 'already' in str(exc).lower()
        asyncio.run(blocked())
        child.kill()
        child.wait(timeout=10)
        async def recovered():
            runtime, _, _ = fixture(tmp_path, ScriptedLLM(), require_existing=True)
            async with runtime:
                assert (await runtime.state())['status'] == 'idle'
        asyncio.run(recovered())
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_large_control_batch_pauses_at_logical_work_limit(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(tool_calls=[NormalizedToolCall(
            id=f'plan-{index}', name='update_plan', arguments={'plan': str(index)}) for index in range(125)]))
        runtime, _, _ = fixture(tmp_path, llm, max_decisions=1, max_actions=1)
        async with runtime:
            state = await runtime.submit('Plan')
            assert state['pending']['kind'] == 'limit' and state['steps'] == 2
            assert len(state['queued_calls']) == 123 and state['plan'] == '1'
            state = await runtime.resume('Continue')
            assert state['pending']['kind'] == 'limit' and state['steps'] == 4
            assert len(state['queued_calls']) == 121 and state['plan'] == '3'
        restored, _, _ = fixture(tmp_path, ScriptedLLM(), max_decisions=1, max_actions=1)
        async with restored:
            assert (await restored.state())['steps'] == 4
    asyncio.run(scenario())


def test_cached_batch_is_bounded_without_dropping_results(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(tool_calls=[NormalizedToolCall(
            id=f'fixture-{index}', name='fixture', arguments={'target': 'example.com'}) for index in range(125)]))
        runtime, tool, _ = fixture(tmp_path, llm, max_decisions=1, max_actions=1)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['pending']['kind'] == 'limit' and state['steps'] == 2
            assert tool.calls == 1 and len(state['results']) == 2 and state['results'][1]['cached']
            assert len(state['queued_calls']) == 123
            state = await runtime.resume('Continue')
            assert state['steps'] == 4 and state['pending']['kind'] == 'limit' and tool.calls == 1
            assert all(result['data'] == {'hosts': ['fixture']} for result in state['results'])
    asyncio.run(scenario())


def test_ownership_releases_after_enter_failure(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM())
        async def failed_open():
            raise RuntimeError('fixture setup failure')
        runtime.store.open = failed_open
        try:
            async with runtime:
                raise AssertionError('Setup should fail')
        except RuntimeError as exc:
            assert 'fixture setup failure' in str(exc)
        restored, _, _ = fixture(tmp_path, ScriptedLLM())
        async with restored:
            assert (await restored.state())['status'] == 'idle'
    asyncio.run(scenario())


def test_canonical_path_alias_shares_session_ownership(tmp_path):
    from core.orchestration import SessionRuntime
    import os

    async def scenario():
        first, _, _ = fixture(tmp_path, ScriptedLLM())
        alias = tmp_path / 'unused' / '..' / ('SESSION.DB' if os.name == 'nt' else 'session.db')
        second = SessionRuntime(target=first.target, registry=first.registry, llm=ScriptedLLM(),
                                gate=first.gate, settings=first.settings, db_path=alias, session_id='test')
        async with first:
            try:
                async with second:
                    raise AssertionError('Canonical path alias must share the owner lock')
            except ValueError as exc:
                assert 'active' in str(exc).lower()
    asyncio.run(scenario())


def test_explicit_step_limit_scales_graph_recursion_budget(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(tool_calls=[NormalizedToolCall(
            id=f'plan-{index}', name='update_plan', arguments={'plan': str(index)}) for index in range(125)]))
        runtime, _, _ = fixture(tmp_path, llm, max_decisions=1, max_actions=1, max_steps=130)
        async with runtime:
            state = await runtime.submit('Plan')
            assert state['pending']['kind'] == 'limit' and state['steps'] == 125
            assert state['plan'] == '124' and not state['queued_calls']
            assert len([message for message in state['messages'] if message['role'] == 'tool']) == 125
    asyncio.run(scenario())


def test_concurrent_enter_same_runtime_keeps_original_owner(tmp_path):
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM())
        ready, proceed = asyncio.Event(), asyncio.Event()
        original_open = runtime.store.open
        async def delayed_open():
            value = await original_open()
            ready.set()
            await proceed.wait()
            return value
        runtime.store.open = delayed_open
        entering = asyncio.create_task(runtime.__aenter__())
        await ready.wait()
        try:
            try:
                await runtime.__aenter__()
                raise AssertionError('Concurrent enter must be rejected')
            except ValueError:
                pass
            assert runtime._ownership.handle is not None
        finally:
            proceed.set()
            await entering
            await runtime.__aexit__(None, None, None)
    asyncio.run(scenario())


def test_xml_completion_only_final_body_line_and_followup_keeps_task(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(content="```xml\n<task_complete/>\n```"),
                          LLMResponse(content="Answer\n<task_complete/>"),
                          LLMResponse(content="Follow-up\n<task_complete/>"))
        runtime, _, _ = fixture(tmp_path, llm)
        async with runtime:
            first = await runtime.submit('Explain')
            assert first['status'] == 'completed' and first['answer'] == 'Answer'
            assert llm.calls == 2
            second = await runtime.submit('Explain more')
            assert second['task_id'] == first['task_id']
            assert second['answer'] == 'Follow-up'
    asyncio.run(scenario())


def test_task_budget_addition_and_new_task_preserve_session_usage(tmp_path):
    async def scenario():
        paid = LLMResponse(content='Need more', token_usage={'input': 6, 'output': 4, 'cost': 0.2})
        llm = ScriptedLLM(paid, LLMResponse(content='Done\n<task_complete/>', token_usage={'input': 1, 'output': 1, 'cost': 0.1}))
        runtime, _, _ = fixture(tmp_path, llm, settings=Settings(MAX_TOKENS_PER_TASK=10, MAX_COST_PER_TASK=0.2))
        async with runtime:
            paused = await runtime.submit('Explain')
            assert paused['pending']['kind'] == 'budget' and paused['used_tokens'] == 10
            topped = await runtime.add_budget(cost=0.2)
            assert topped['max_tokens'] == 0 and topped['max_cost'] == 0.4 and topped['used_tokens'] == 10
            done = await runtime.resume('Continue')
            assert done['status'] == 'completed' and done['used_tokens'] == 12
            fresh = await runtime.new_task()
            assert fresh['task_id'] != done['task_id'] and fresh['used_tokens'] == 0
            assert fresh['session_used_tokens'] == 12 and fresh['max_tokens'] == 0
            assert fresh['max_cost'] == 0.2 and abs(fresh['session_used_cost'] - 0.3) < 1e-12
            assert not fresh['results'] and fresh['status'] == 'idle'
        restored, _, _ = fixture(tmp_path, ScriptedLLM(), settings=Settings(MAX_TOKENS_PER_TASK=10, MAX_COST_PER_TASK=0.2))
        async with restored:
            state = await restored.state()
            assert state['used_tokens'] == 0 and state['session_used_tokens'] == 12
    asyncio.run(scenario())


def test_soft_budget_does_not_block_authorized_tools():
    guard = BudgetGuard(max_cost=100, used_cost=85)
    assert guard.allows(2) and guard.allows(1)


def test_marker_with_native_calls_waits_for_following_completion(tmp_path):
    async def scenario():
        llm = ScriptedLLM(LLMResponse(content='Proceed\n<task_complete/>', tool_calls=[
            NormalizedToolCall(id='tool', name='fixture', arguments={'target': 'example.com'})]),
            LLMResponse(content='Finished\n<task_complete/>'))
        runtime, tool, _ = fixture(tmp_path, llm)
        async with runtime:
            state = await runtime.submit('Inspect')
            assert state['status'] == 'completed' and llm.calls == 2 and tool.calls == 1
            assert state['answer'] == 'Finished'
    asyncio.run(scenario())


def test_unknown_timeout_survives_new_task_and_archive_keeps_completion(tmp_path):
    import json
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(LLMResponse(content='Done\n<task_complete/>')))
        async with runtime:
            done = await runtime.submit('Explain')
            await runtime.store.start('test', 'late', 'fixture', {'target': 'example.com'}, done['task_id'])
            timeout = ToolResult(name='fixture', success=False, status='timeout', outcome_unknown=True).model_dump()
            await runtime.store.complete('test', 'late', timeout)
            fresh = await runtime.new_task()
            found = await runtime.store.lookup('test', 'new', 'fixture', {'target': 'example.com'}, fresh['task_id'])
            assert found['status'] == 'started' and found['result']['outcome_unknown']
            async with runtime.store.connection.execute('SELECT state FROM task_archive WHERE task_id=?', (done['task_id'],)) as cursor:
                archived = json.loads((await cursor.fetchone())[0])
            assert archived['status'] == 'completed' and archived['answer'] == 'Done'
    asyncio.run(scenario())


def test_compact_context_preserves_goal_recent_input_and_tool_pairs():
    from core.orchestration.model_context import model_messages
    from types import SimpleNamespace
    history = [{'role': 'system', 'content': 'main'}, {'role': 'user', 'content': 'goal'}]
    for index in range(12):
        history += [{'role': 'assistant', 'content': 'old ' * 1000, 'tool_calls': [{'id': str(index)}]},
                    {'role': 'tool', 'tool_call_id': str(index), 'content': 'result ' * 1000}]
    history += [{'role': 'user', 'content': 'latest instruction'}]
    state = {'messages': history, 'task_goal': 'goal', 'plan': 'plan', 'target': 'example.com', 'results': []}
    request = model_messages(state, SimpleNamespace(current_level=lambda: 1), BudgetGuard(), 1000)
    assert len(request) < len(history)
    assert request[-1]['content'] == 'latest instruction'
    assert any('goal' in message['content'] and 'plan' in message['content'] for message in request if message['role'] == 'system')
    ids = {call['id'] for message in request for call in message.get('tool_calls', [])}
    assert ids == {message['tool_call_id'] for message in request if message['role'] == 'tool'}
    assert history[2]['content'] == 'old ' * 1000


def test_indented_code_marker_does_not_complete():
    from core.orchestration.completion import completion_text
    assert not completion_text('Example:\n\n    <task_complete/>')[1]
    assert not completion_text('```xml\n<task_complete/>')[1]
    assert completion_text('Conclusion\n<task_complete/>\n')[0] == 'Conclusion'


def test_context_index_is_bounded_and_protocol_reminders_are_deduplicated():
    import json
    from types import SimpleNamespace
    from core.orchestration.model_context import model_messages
    from core.orchestration.completion import REMINDER
    state = {'messages': [{'role': 'system', 'content': 'main'}] +
             [{'role': 'system', 'content': REMINDER}] * 20 + [{'role': 'user', 'content': 'latest'}],
             'task_goal': 'goal', 'results': [{'name': 'fixture', 'summary': 'x' * 10000,
                'error': 'y' * 10000, 'evidence': ['fixture://evidence/' + 'z' * 2000] * 30,
                'artifacts': [{'id': 'real', 'size_bytes': 200, 'path': 'z' * 2000, 'description': 'z' * 10000}] * 30}] * 50}
    request = model_messages(state, SimpleNamespace(current_level=lambda: 0), BudgetGuard(), 28000)
    assert sum(message['content'] == REMINDER for message in request) == 1
    assert len(json.dumps(request, ensure_ascii=False)) < 15000
    assert 'total_results' in request[-2]['content'] and 'artifact_read' in request[-2]['content']
    assert '"id": "real"' in request[-2]['content']
    assert len(state['results']) == 50 and len(state['messages']) == 22
