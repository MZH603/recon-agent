import asyncio
from types import SimpleNamespace as NS
import pytest
from model.litellm_adapter import LiteLLMAdapter
from core.llm import LLMService
from efficiency.budget_guard import BudgetGuard
from utils.config import Settings


def sdk_response(cost=None):
    return NS(choices=[NS(message=NS(content='ok', tool_calls=None))],
              usage=NS(prompt_tokens=3, completion_tokens=4), model='fixture',
              _hidden_params={'response_cost': cost})


def test_sdk_provider_help_is_quiet_but_unknown_cost_and_errors_remain(monkeypatch, capsys):
    from model.litellm_adapter import _import_litellm
    import litellm
    monkeypatch.setattr(litellm, 'suppress_debug_info', False)
    sdk = _import_litellm()
    unknown = '__recon_unregistered_endpoint_model__'
    raw = sdk.ModelResponse(model=unknown, usage={'prompt_tokens': 3, 'completion_tokens': 4,
        'total_tokens': 7}, choices=[{'index': 0, 'finish_reason': 'stop',
        'message': {'role': 'assistant', 'content': 'successful reply'}}])
    response = LiteLLMAdapter('openai/' + unknown)._to_response(raw, sdk)
    assert response.content == 'successful reply'
    assert response.token_usage['cost'] is None and not response.token_usage['cost_known']
    with pytest.raises(sdk.exceptions.BadRequestError):
        sdk.get_llm_provider(model=unknown)
    captured = capsys.readouterr()
    assert 'Provider List:' not in captured.out + captured.err


@pytest.mark.parametrize('cost', [0, 0.125])
def test_adapter_captures_known_cost_and_custom_credential(monkeypatch, cost):
    captured=[]
    async def complete(**kwargs):
        captured.append(kwargs)
        return sdk_response(cost)
    monkeypatch.setenv('FIXTURE_API_KEY', 'fixture-secret')
    monkeypatch.setattr('model.litellm_adapter._import_litellm', lambda: NS(acompletion=complete))
    response=asyncio.run(LiteLLMAdapter('fixture', api_key_env='FIXTURE_API_KEY').complete([]))
    assert response.token_usage['cost'] == cost
    assert response.token_usage['cost_known'] is True
    assert captured[0]['api_key'] == 'fixture-secret'


@pytest.mark.parametrize('cost', [None, -1, float('nan'), float('inf')])
def test_pricing_failure_never_retries_a_successful_paid_request(monkeypatch, cost):
    calls=[]
    async def complete(**kwargs):
        calls.append(1)
        return sdk_response(cost)
    def pricing(**kwargs):
        raise ValueError('model price unavailable')
    monkeypatch.setattr('model.litellm_adapter._import_litellm',
                        lambda: NS(acompletion=complete, completion_cost=pricing))
    response=asyncio.run(LiteLLMAdapter('fixture', max_retries=2).complete([]))
    assert calls == [1]
    assert response.token_usage['cost'] is None
    assert response.token_usage['cost_known'] is False


def test_sdk_price_fallback_and_llmservice_registers_cost_once(monkeypatch):
    async def complete(**kwargs):
        return sdk_response()
    monkeypatch.setattr('model.litellm_adapter._import_litellm',
                        lambda: NS(acompletion=complete, completion_cost=lambda **kwargs: 0.25))
    adapter=LiteLLMAdapter('fixture')
    monkeypatch.setattr('core.llm.build_provider', lambda *args: adapter)
    guard=BudgetGuard()
    service=LLMService(Settings(), guard=guard)
    response=asyncio.run(service.complete([]))
    assert response.token_usage['cost'] == guard.used_cost == 0.25
    assert guard.used_tokens == 7


def test_unknown_cost_is_durable_and_valid_cost_not_double_counted(tmp_path):
    from tests.unit.test_session_graph import fixture, ScriptedLLM, response
    async def scenario():
        first=response('ask_user', {'question': 'Next?'})
        first.token_usage={'input': 3, 'output': 4, 'cost': 0.25}
        second=response('ask_user', {'question': 'Next again?'})
        second.token_usage={'input': 2, 'output': 1, 'cost': None, 'cost_known': False}
        llm=ScriptedLLM(first, second)
        runtime, _, _=fixture(tmp_path, llm)
        async with runtime:
            await runtime.submit('test')
            state=await runtime.resume('continue')
            assert state['used_cost'] == 0.25 and state['used_tokens'] == 10
            assert state['cost_unknown_calls'] == 1
            # Model usage journal is independently committed before graph checkpoint.
            await runtime.graph.aupdate_state(runtime.config, {'cost_unknown_calls': 0})
        restored, _, _=fixture(tmp_path, ScriptedLLM())
        async with restored:
            state=await restored.state()
            assert state['cost_unknown_calls'] == 1
    asyncio.run(scenario())


def test_old_usage_schema_can_be_migrated_by_concurrent_sessions(tmp_path):
    import sqlite3
    from core.orchestration.store import SessionStore
    db=tmp_path / 'old.db'
    with sqlite3.connect(db) as connection:
        connection.execute('CREATE TABLE session_usage(session_id TEXT PRIMARY KEY, decisions INTEGER NOT NULL DEFAULT 0, used_tokens INTEGER NOT NULL DEFAULT 0, used_cost REAL NOT NULL DEFAULT 0)')
        connection.execute("INSERT INTO session_usage VALUES ('existing',2,10,0.25)")
    async def scenario():
        stores=[SessionStore(db), SessionStore(db)]
        try:
            await asyncio.gather(*(s.open() for s in stores))
            assert (await stores[0].usage('existing')) == dict(decisions=2, used_tokens=10, used_cost=0.25, cost_unknown_calls=0)
            await stores[0].save_usage('existing',3,20,0.5,1)
            assert (await stores[1].usage('existing'))['cost_unknown_calls'] == 1
        finally:
            await asyncio.gather(*(s.close() for s in stores))
    asyncio.run(scenario())


def test_estimated_usage_is_marked_and_legacy_totals_bind_once(tmp_path):
    from tests.unit.test_session_graph import fixture, ScriptedLLM
    from model.base import LLMResponse
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM(LLMResponse(content='Done\n<task_complete/>',
                              token_usage={'input': 3, 'output': 4, 'estimated': True})))
        async with runtime:
            state = await runtime.submit('Explain')
            assert state['used_tokens'] == 7 and state['usage_estimated_calls'] == 1
            task_id = state['task_id']
            await runtime.new_task()
            old = await runtime.store.task_usage('test', task_id)
            assert old['used_tokens'] == 7
        restored, _, _ = fixture(tmp_path, ScriptedLLM())
        async with restored:
            assert (await restored.state())['used_tokens'] == 0
        legacy, _, _ = fixture(tmp_path / 'legacy', ScriptedLLM())
        async with legacy:
            await legacy.store.connection.execute('DELETE FROM task_usage')
            await legacy.store.save_usage('test', 3, 18, 0.3, 2)
            await legacy.graph.aupdate_state(legacy.config, {'used_tokens': 20, 'used_cost': 0.4})
            await legacy._restore_budget()
            state = await legacy.state()
            assert state['used_tokens'] == state['session_used_tokens'] == 20
            assert state['used_cost'] == state['session_used_cost'] == 0.4
            fresh = await legacy.new_task()
            assert fresh['used_tokens'] == 0 and fresh['session_used_tokens'] == 20
    asyncio.run(scenario())


def test_cumulative_tokens_above_deprecated_task_cap_keep_running(tmp_path):
    from tests.unit.test_session_graph import fixture, ScriptedLLM
    from model.base import LLMResponse
    async def scenario():
        llm = ScriptedLLM(LLMResponse(content='Keep going', token_usage={'input': 500, 'output': 500, 'cost': 0.01}),
                          LLMResponse(content='Done\n<task_complete/>', token_usage={'input': 500, 'output': 500, 'cost': 0.01}))
        runtime, _, _ = fixture(tmp_path, llm, settings=Settings(MAX_TOKENS_PER_TASK=10))
        async with runtime:
            state = await runtime.submit('Explain')
            assert state['status'] == 'completed' and llm.calls == 2
            assert state['used_tokens'] == state['session_used_tokens'] == 2000
            assert state['max_tokens'] == runtime.guard.max_tokens == 0
    asyncio.run(scenario())


def test_restored_positive_token_cap_is_inactive_and_usage_is_preserved(tmp_path):
    from tests.unit.test_session_graph import fixture, ScriptedLLM
    from model.base import LLMResponse
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM())
        async with runtime:
            current = await runtime.state()
            await runtime.store.save_task_usage('test', current['task_id'], 0, 1000, 0.1, 0, 0)
            await runtime.store.connection.execute('UPDATE task_usage SET max_tokens=10 WHERE task_id=?', (current['task_id'],))
            await runtime.store.connection.commit()
            await runtime.graph.aupdate_state(runtime.config,
                runtime._pause_update('budget', 'Legacy token limit reached'), as_node='decide')
            await runtime.graph.ainvoke(None, runtime.config)
        llm = ScriptedLLM(LLMResponse(content='Done\n<task_complete/>', token_usage={'input': 3, 'output': 4, 'cost': 0.01}))
        restored, _, _ = fixture(tmp_path, llm)
        async with restored:
            before = await restored.state()
            assert before['used_tokens'] == 1000 and before['max_tokens'] == restored.guard.max_tokens == 0
            done = await restored.resume('Continue')
            assert done['status'] == 'completed' and llm.calls == 1
            assert done['used_tokens'] == done['session_used_tokens'] == 1007
            stored = await restored.store.task_usage('test', current['task_id'])
            assert stored['max_tokens'] == 10
    asyncio.run(scenario())


def test_budget_additions_reject_tokens_and_allow_cost_only(tmp_path):
    from tests.unit.test_session_graph import fixture, ScriptedLLM
    async def scenario():
        runtime, _, _ = fixture(tmp_path, ScriptedLLM())
        async with runtime:
            for tokens in (1, -1, True, 1.5):
                with pytest.raises(ValueError, match='token|Token'):
                    await runtime.add_budget(tokens=tokens)
            for cost in (float('nan'), float('inf'), -1):
                with pytest.raises(ValueError):
                    await runtime.add_budget(cost=cost)
            current = await runtime.state()
            topped = await runtime.add_budget(tokens=0, cost=0.25)
            assert topped['max_cost'] == current['max_cost'] + 0.25
            assert topped['used_tokens'] == current['used_tokens'] and topped['used_cost'] == current['used_cost']
            assert topped['max_tokens'] == 0
    asyncio.run(scenario())


def test_state_context_preview_uses_current_settings_without_checkpoint_mutation(tmp_path):
    from tests.unit.test_session_graph import fixture, ScriptedLLM
    async def scenario():
        llm = ScriptedLLM()
        runtime, _, _ = fixture(tmp_path, llm)
        async with runtime:
            history = [{'role': 'system', 'content': 'main'}, {'role': 'user', 'content': 'Explain this task'}]
            saved_context = dict(context_history=history, context_cursor=2, context_compactions=3,
                context_before_tokens=999, context_saved_tokens=888, context_compressed=True,
                context_limited=True)
            await runtime.graph.aupdate_state(runtime.config, {'messages': history, **saved_context}, as_node='decide')
            before = await runtime.graph.aget_state(runtime.config)
            runtime.settings.CONTEXT_BUDGET = 200_000
            runtime.settings.COMPACT_TRIGGER_RATIO = 0.6
            preview = await runtime.state()
            assert preview['context_capacity'] == 200_000
            assert preview['context_trigger_tokens'] == 120_000
            assert preview['context_tokens'] > 0 and preview['context_estimated']
            assert all(preview[key] == value for key, value in saved_context.items())
            after = await runtime.graph.aget_state(runtime.config)
            assert after.values == before.values and llm.calls == 0
    asyncio.run(scenario())


def test_lazy_startup_context_estimate_rejects_oversized_chinese_input():
    from core.orchestration.model_context import prepare_context
    from core.orchestration.state import initial_state
    from model.lazy import LazyLLM
    llm = LazyLLM(Settings(), 'fixture')
    state = initial_state('test', 'example.com', 'main')
    state['messages'].append({'role': 'user', 'content': '汉' * 120_000})
    _, updates = prepare_context(state, NS(current_level=lambda: 0), llm.guard,
                                 100_000, count_tokens=llm.count_tokens)
    assert updates['context_tokens'] >= 120_000
    assert updates['context_limited']
    assert llm.service is None
