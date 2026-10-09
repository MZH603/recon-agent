"""The request working set is independent of cumulative usage and durable history."""
import asyncio
import copy
import json
from types import SimpleNamespace

from core.orchestration import model_context
from core.orchestration.state import initial_state
from efficiency.budget_guard import BudgetGuard


GATE = SimpleNamespace(current_level=lambda: 0)


def prepare(state, capacity=100000, **kwargs):
    return model_context.prepare_context(state, GATE, BudgetGuard(), capacity, **kwargs)


def history_state():
    state = initial_state('fixture', 'example.com', 'Preserve system instruction')
    state['messages'].append({'role': 'user', 'content': 'Preserve original goal'})
    for index in range(12):
        state['messages'].extend([
            {'role': 'assistant', 'content': 'old reasoning ' * 1000,
             'tool_calls': [{'id': f'call-{index}', 'type': 'function',
                             'function': {'name': 'fixture', 'arguments': '{}'}}]},
            {'role': 'tool', 'tool_call_id': f'call-{index}', 'content': 'old evidence ' * 1000},
        ])
    state['messages'].append({'role': 'user', 'content': 'Preserve latest constraint'})
    state['task_goal'], state['plan'] = 'real goal', 'real plan'
    state['results'] = [{'name': 'fixture', 'evidence': ['fixture://real'],
                         'artifacts': [{'id': 'real-artifact', 'path': '/real/output'}]}]
    return state


def test_under_threshold_preserves_long_old_history_and_ignores_cumulative_tokens():
    state = history_state()
    before = copy.deepcopy(state)
    request, updates = prepare(state, capacity=1000000)
    assert [m for m in request if m['role'] != 'system'] == state['messages'][1:]
    assert not updates['context_compressed'] and updates['context_compactions'] == 0
    assert state == before
    dynamic = next(m['content'] for m in request if 'evidence_index' in m['content'])
    assert 'used_tokens' not in dynamic and 'max_tokens' not in dynamic


def test_threshold_compacts_atomic_batches_preserves_instructions_and_real_index():
    state = history_state()
    original = copy.deepcopy(state['messages'])
    _, preview = prepare(state, compact=False)
    capacity = int(preview['context_tokens'] / .70)
    request, updates = prepare(state, capacity=capacity)
    assert updates['context_compressed'] and updates['context_compactions'] == 1
    assert updates['context_tokens'] < updates['context_before_tokens']
    assert updates['context_saved_tokens'] == updates['context_before_tokens'] - updates['context_tokens']
    assert updates['context_tokens'] <= capacity * .50
    assert all(any(m == instruction for m in request) for instruction in original if instruction['role'] in ('system', 'user'))
    calls = {c['id'] for m in request for c in m.get('tool_calls', [])}
    assert calls == {m['tool_call_id'] for m in request if m['role'] == 'tool'}
    text = json.dumps(request)
    assert all(value in text for value in ('real-artifact', 'fixture://real', 'real goal', 'real plan'))
    assert state['messages'] == original
    assert not any('evidence_index' in m.get('content', '') for m in updates['context_history'])


def test_schema_size_triggers_compaction_and_model_counter_receives_schemas():
    state = history_state()
    seen = []
    def count(text):
        seen.append(text)
        return max(1, len(text) // 3)
    _, baseline = prepare(state, compact=False, count_tokens=count)
    capacity = int(baseline['context_tokens'] / .69)
    schemas = [{'type': 'function', 'function': {'name': 'schema-marker', 'description': 'schema ' * 5000}}]
    _, updates = prepare(state, capacity=capacity, tools=schemas, count_tokens=count)
    assert updates['context_compressed']
    assert any('schema-marker' in text for text in seen)
    assert updates['context_estimated']


def test_replay_and_resume_do_not_reinflate_history_or_recount_compression():
    state = history_state()
    _, updates = prepare(state, capacity=18000)
    assert updates['context_compressed']
    state.update(updates)
    active = copy.deepcopy(state['context_history'])
    _, repeated = prepare(state, capacity=18000)
    assert repeated['context_history'] == active
    assert repeated['context_compactions'] == 1 and not repeated['context_compressed']
    assert repeated['context_before_tokens'] == updates['context_before_tokens']
    assert repeated['context_saved_tokens'] == updates['context_saved_tokens']
    state.update(repeated)
    state['messages'].append({'role': 'assistant', 'content': 'new-tail-marker'})
    request, resumed = prepare(state, capacity=18000)
    assert sum(m.get('content') == 'new-tail-marker' for m in request) == 1
    assert resumed['context_cursor'] == len(state['messages'])
    assert resumed['context_compactions'] == 1


def test_preview_leaves_working_set_and_last_compression_metrics_untouched():
    state = history_state()
    _, updates = prepare(state, capacity=18000)
    state.update(updates)
    snapshot = copy.deepcopy(state)
    state['messages'].append({'role': 'assistant', 'content': 'tail'})
    before = copy.deepcopy(state)
    _, preview = prepare(state, capacity=20000, compact=False)
    assert set(preview) == {'context_tokens', 'context_capacity', 'context_trigger_tokens', 'context_estimated'}
    assert state == before
    assert state['context_compressed'] == snapshot['context_compressed']


def test_invalid_cursor_rebuilds_from_original_and_required_content_can_limit():
    state = initial_state('fixture', 'example.com', 'system')
    state['messages'].append({'role': 'user', 'content': 'required ' * 10000})
    state.update(context_cursor=999, context_history=[{'role': 'assistant', 'content': 'stale-marker'}])
    request, updates = prepare(state, capacity=1000)
    assert updates['context_limited'] and not updates['context_compressed']
    assert updates['context_cursor'] == len(state['messages'])
    assert 'stale-marker' not in json.dumps(request)
    assert state['messages'][1] in request


def test_new_task_initial_state_resets_working_set_and_context_metrics():
    state = initial_state('fixture', 'example.com', 'system')
    assert state.get('context_history') == [] and state.get('context_cursor') == 0
    assert state.get('context_compactions') == state.get('context_saved_tokens') == 0
    assert state.get('context_compressed') is False and state.get('context_limited') is False


def decision_fixture(state, outcome, capacity=18000):
    from core.orchestration.decisions import DecisionNodes
    from model.base import LLMResponse
    events, requests, saves = [], [], []
    class Store:
        async def usage(self, session):
            return {'decisions': 0}
        async def task_usage(self, session, task):
            return {'cost_unknown_calls': 0, 'usage_estimated_calls': 0}
        async def save_task_usage(self, *args):
            saves.append(args)
    class Model:
        async def complete(self, messages, tools):
            requests.append(messages)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome or LLMResponse(content='done\n<task_complete/>')
    node = SimpleNamespace(store=Store(), session_id='fixture', guard=BudgetGuard(),
                           max_decisions=15, gate=GATE, llm=Model(), on_event=None,
                           settings=SimpleNamespace(CONTEXT_BUDGET=capacity, COMPACT_TRIGGER_RATIO=.7),
                           registry=SimpleNamespace(select_tools=lambda names: None, specs=lambda: []))
    node._emit = lambda kind, **values: events.append({'kind': kind, **values})
    node._pause_update = lambda kind, question, **values: {
        'status': 'paused', 'route': 'pause', 'pending': {'kind': kind, 'question': question, **values}}
    return DecisionNodes, node, events, requests, saves


def test_oversized_required_context_pauses_without_model_or_decision_reservation():
    state = initial_state('fixture', 'example.com', 'system')
    state['messages'].append({'role': 'user', 'content': 'required ' * 10000})
    cls, node, events, requests, saves = decision_fixture(state, None, capacity=1000)
    update = asyncio.run(cls._decide(node, state))
    assert update['pending']['kind'] == 'context_limit'
    assert '/new' in update['pending']['question']
    assert update['context_limited'] and not requests and not saves
    assert events[0]['kind'] == 'context' and events[0]['context_tokens'] > 1000


def test_decision_persists_compaction_and_emits_before_model_on_success_or_error():
    from model.base import ModelUnavailable
    from efficiency.budget_guard import BudgetExhausted
    for outcome in (None, ModelUnavailable('fixture outage'), BudgetExhausted('fixture cost limit')):
        state = history_state()
        original = copy.deepcopy(state['messages'])
        cls, node, events, requests, _ = decision_fixture(state, outcome)
        update = asyncio.run(cls._decide(node, state))
        assert update['context_compressed'] and update['context_compactions'] == 1
        assert update['context_cursor'] == len(original)
        assert events[0]['kind'] == 'context' and events[1]['kind'] == 'model_start'
        assert events[0]['context_tokens'] == update['context_tokens']
        assert len(requests) == 1 and state['messages'] == original
        assert 'context_history' not in events[0]


def test_cancelled_request_still_emits_accurate_live_context_before_model():
    state = history_state()
    cls, node, events, requests, _ = decision_fixture(state, asyncio.CancelledError())
    async def scenario():
        try:
            await cls._decide(node, state)
            assert False, 'Cancellation must propagate'
        except asyncio.CancelledError:
            pass
    asyncio.run(scenario())
    assert events[0]['kind'] == 'context' and events[0]['context_compressed']
    assert events[0]['context_tokens'] <= 18000
    assert len(requests) == 1


def test_xml_tool_data_compacts_but_xml_looking_operator_instructions_stay_complete():
    state = history_state()
    for message in state['messages']:
        if message['role'] == 'assistant':
            message.pop('tool_calls')
            message['content'] = '<tool_call><tool_name>fixture</tool_name><parameters/></tool_call>'
        elif message['role'] == 'tool':
            message.pop('tool_call_id')
            message.update(role='user', content='<tool_result>' + message['content'] + '</tool_result>',
                           _context_tool_result=True)
    instruction = {'role': 'user', 'content': '<tool_result>Literal operator constraint</tool_result>'}
    state['messages'].insert(2, instruction)
    original = copy.deepcopy(state['messages'])
    request, updates = prepare(state, capacity=12000)
    assert updates['context_compressed'] and not updates['context_limited']
    assert instruction in request and original[-1] in request
    assert all('_context_tool_result' not in message for message in request)
    calls = [m for m in request if m['role'] == 'assistant' and m['content'].startswith('<tool_call>')]
    replies = [m for m in request if m['role'] == 'user' and m['content'].startswith('<tool_result>old evidence')]
    assert len(calls) == len(replies) == 1
    assert state['messages'] == original
