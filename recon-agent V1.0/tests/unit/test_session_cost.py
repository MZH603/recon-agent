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
