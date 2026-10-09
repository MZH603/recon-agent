"""Real incremental contracts using an offline asynchronous SDK fixture."""
import asyncio
import json
from types import SimpleNamespace as NS

import pytest

from model.base import LLMProvider, LLMResponse, ModelUnavailable
from model.litellm_adapter import LiteLLMAdapter
from model.registry import FallbackProvider


def chunk(content=None, calls=None, usage=None, finish_reason=None):
    delta = NS(content=content, tool_calls=calls)
    return NS(model='fixture', choices=[NS(index=0, delta=delta, finish_reason=finish_reason)] if usage is None else [],
              usage=usage)


def terminal():
    return chunk(finish_reason='stop')


def call(index, name=None, arguments='', identifier=None):
    return NS(index=index, id=identifier, function=NS(name=name, arguments=arguments))


class Stream:
    def __init__(self, values, before=None):
        self.values, self.before, self.closed = values, before, False

    async def __aiter__(self):
        for value in self.values:
            if self.before:
                self.before()
            await asyncio.sleep(0)
            if isinstance(value, BaseException):
                raise value
            yield value

    async def aclose(self):
        self.closed = True


def sdk(monkeypatch, streams):
    requests = []
    async def completion(**kwargs):
        requests.append(kwargs)
        value = streams.pop(0)
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setattr('model.litellm_adapter._import_litellm', lambda: NS(acompletion=completion))
    return requests


def test_deltas_precede_final_and_interleaved_calls_usage_are_merged(monkeypatch):
    events = []
    stream = Stream([chunk('hello '), chunk('world', [call(1, 'ask_user', '{"question":"', 'b'),
                                                       call(0, 'finish_task', '{"answer":"', 'a')]),
                     chunk(calls=[call(0, arguments='done"}'), call(1, arguments='next?"}')]),
                     terminal(), chunk(usage=NS(prompt_tokens=11, completion_tokens=7))])
    requests = sdk(monkeypatch, [stream])
    async def scenario():
        task = asyncio.create_task(LiteLLMAdapter('fixture').complete_stream([], on_delta=events.append))
        while not events:
            await asyncio.sleep(0)
        assert not task.done(), 'delta must arrive before the final response'
        result = await task
        assert result.content == 'hello world'
        assert [(c.id, c.name, c.arguments) for c in result.tool_calls] == [
            ('a', 'finish_task', {'answer': 'done'}), ('b', 'ask_user', {'question': 'next?'})]
        assert result.token_usage['input'] == 11 and result.token_usage['output'] == 7
    asyncio.run(scenario())
    assert requests[0]['stream'] is True
    assert requests[0]['stream_options'] == {'include_usage': True}
    assert stream.closed


def test_old_provider_default_stream_is_backward_compatible():
    class Old(LLMProvider):
        async def complete(self, messages, tools=None):
            return LLMResponse(content='legacy')
        def count_tokens(self, text):
            return 1
    events=[]
    assert asyncio.run(Old().complete_stream([], on_delta=events.append)).content == 'legacy'
    assert events[0].content == 'legacy'


def test_reasoning_stream_is_observed_preserved_and_counted(monkeypatch):
    value = chunk()
    value.choices[0].delta.reasoning_content = '内部推理'
    events = []
    stream = Stream([value, chunk('answer'), terminal()])
    sdk(monkeypatch, [stream])
    result = asyncio.run(LiteLLMAdapter('fixture').complete_stream([], on_delta=events.append))
    assert any(event.kind == 'reasoning' and event.content == '内部推理' for event in events)
    assert result.reasoning_content == '内部推理'
    assert 0 < result.token_usage['output'] < len('内部推理answer'.encode())
    assert result.token_usage['estimated']


def test_partial_failure_never_retries_or_falls_back_and_error_is_safe(monkeypatch):
    stream = Stream([chunk('visible'), OSError('SECRET https://private.invalid')])
    requests = sdk(monkeypatch, [stream, Stream([chunk('wrong')])])
    fallback = FallbackProvider([LiteLLMAdapter('one', max_retries=2), LiteLLMAdapter('two')], ['one', 'two'])
    with pytest.raises(ModelUnavailable) as failure:
        asyncio.run(fallback.complete_stream([], on_delta=lambda e: None))
    assert 'SECRET' not in str(failure.value) and 'private' not in str(failure.value)
    assert len(requests) == 1 and stream.closed


def test_prechunk_retry_and_fallback_are_observed(monkeypatch):
    requests = sdk(monkeypatch, [OSError('no'), OSError('no'), Stream([chunk('ok'), terminal()])])
    async def no_sleep(seconds):
        pass
    monkeypatch.setattr('model.litellm_adapter.asyncio.sleep', no_sleep)
    events=[]
    provider=FallbackProvider([LiteLLMAdapter('one', max_retries=1), LiteLLMAdapter('two')], ['one', 'two'])
    assert asyncio.run(provider.complete_stream([], on_delta=events.append)).content == 'ok'
    assert [e.kind for e in events if e.kind in ('retry', 'fallback')] == ['retry', 'fallback']
    assert len(requests) == 3


def test_timeout_covers_consumption_and_cancel_closes_stream(monkeypatch):
    class Waiting(Stream):
        async def __aiter__(self):
            yield chunk('started')
            await asyncio.Event().wait()
    async def scenario():
        for cancel in (False, True):
            stream=Waiting([])
            sdk(monkeypatch, [stream])
            ready=asyncio.Event()
            adapter=LiteLLMAdapter('fixture', timeout=.02, max_retries=0)
            task=asyncio.create_task(adapter.complete_stream([], on_delta=lambda e: ready.set()))
            await ready.wait()
            if cancel:
                task.cancel()
            with pytest.raises(asyncio.CancelledError if cancel else ModelUnavailable):
                await task
            assert stream.closed
    asyncio.run(scenario())


@pytest.mark.parametrize('failure', [OSError('lost'), asyncio.CancelledError()])
def test_service_registers_partial_usage_and_complete_usage_once(monkeypatch, failure):
    from core.llm import LLMService
    from utils.config import Settings
    stream=Stream([chunk('part'), failure])
    sdk(monkeypatch, [stream])
    monkeypatch.setattr('core.llm.build_provider', lambda *args: LiteLLMAdapter('fixture', max_retries=0))
    service=LLMService(Settings())
    with pytest.raises(asyncio.CancelledError if isinstance(failure, asyncio.CancelledError) else ModelUnavailable):
        asyncio.run(service.complete_stream([{'role':'user','content':'hello'}], on_delta=lambda e: None))
    assert service.guard.used_tokens > 0
    assert service.guard.used_cost == 0
    sdk(monkeypatch, [Stream([chunk('ok'), terminal(), chunk(usage=NS(prompt_tokens=10, completion_tokens=5))])])
    before=service.guard.used_tokens
    asyncio.run(service.complete_stream([], on_delta=lambda e: None))
    assert service.guard.used_tokens == before + 15


def test_real_sdk_chunks_preserve_known_pricing_and_missing_usage_is_estimated(monkeypatch):
    import litellm
    async def completion(**kwargs):
        return Stream([litellm.ModelResponse(stream=True, model='gpt-4o-mini', choices=[
            {'index':0, 'delta':{'role':'assistant', 'content':'hello'}, 'finish_reason':'stop'}]),
            litellm.ModelResponse(stream=True, model='gpt-4o-mini', choices=[],
                usage={'prompt_tokens':10, 'completion_tokens':5, 'total_tokens':15})])
    monkeypatch.setattr(litellm, 'acompletion', completion)
    result=asyncio.run(LiteLLMAdapter('gpt-4o-mini').complete_stream([]))
    assert result.token_usage['cost_known'] and result.token_usage['cost'] > 0
    sdk(monkeypatch, [Stream([chunk('long enough visible response'), terminal()])])
    messages=[{'role':'user','content':'中文 hello'}]
    result=asyncio.run(LiteLLMAdapter('fixture').complete_stream(messages))
    assert 0 < result.token_usage['input'] < len(json.dumps(messages, ensure_ascii=False).encode('utf-8'))
    assert result.token_usage['estimated']
    assert 0 < result.token_usage['output'] < len('long enough visible response'.encode('utf-8'))
    assert result.token_usage['cost_known'] is False


def test_valid_tool_json_eof_without_finish_marker_never_executes(tmp_path, monkeypatch):
    from core.llm import LLMService
    from tests.unit.test_session_graph import fixture
    from utils.config import Settings
    stream=Stream([chunk(calls=[call(0, 'fixture', '{"target":"example.com"}', 'valid')])])
    requests=sdk(monkeypatch, [stream])
    monkeypatch.setattr('core.llm.build_provider', lambda *args: LiteLLMAdapter('fixture', max_retries=0))
    async def scenario():
        runtime, tool, _=fixture(tmp_path, LLMService(Settings()), on_event=lambda e: None)
        async with runtime:
            state=await runtime.submit('inspect')
            assert tool.calls == 0, 'valid JSON is not proof that the stream ended completely'
            assert state['pending']['kind']=='model_unavailable'
            assert state['used_tokens'] > 0 and state['cost_unknown_calls']==1
    asyncio.run(scenario())
    assert len(requests)==1 and stream.closed


def test_partial_usage_preserves_actual_dimensions_and_known_cost():
    from model.base import StreamUsage, StreamEvent, conservative_tokens
    partial = StreamUsage()
    partial.add(StreamEvent('content', content='中文 answer'))
    partial.add(StreamEvent('usage', token_usage={'input': 9, 'cost': 0.25}))
    consumed = partial.partial([{'role': 'user', 'content': 'hello'}], lambda text: 3)
    assert consumed['input'] == 9 and consumed['output'] == 3
    assert consumed['estimated'] and consumed['cost'] == 0.25 and consumed['cost_known']
    assert conservative_tokens('中文', lambda text: 2) == 2
    assert 0 < conservative_tokens('中文', lambda text: None) < len('中文'.encode())


def test_synchronous_missing_usage_is_estimated_without_losing_known_cost(monkeypatch):
    async def complete(**kwargs):
        return NS(choices=[NS(message=NS(content='中文 answer', tool_calls=None))], usage=None,
                  model='fixture', _hidden_params={'response_cost': 0.25})
    monkeypatch.setattr('model.litellm_adapter._import_litellm', lambda: NS(acompletion=complete))
    response = asyncio.run(LiteLLMAdapter('fixture').complete([{'role': 'user', 'content': '中文 goal'}]))
    assert response.token_usage['input'] > 0 and response.token_usage['output'] > 0
    assert response.token_usage['estimated'] and response.token_usage['cost'] == 0.25


def test_stream_incomplete_usage_preserves_known_input_and_estimates_output(monkeypatch):
    sdk(monkeypatch, [Stream([chunk('visible response'), terminal(), chunk(usage=NS(prompt_tokens=9))])])
    response = asyncio.run(LiteLLMAdapter('fixture').complete_stream([{'role': 'user', 'content': 'hello'}]))
    assert response.token_usage['input'] == 9
    assert response.token_usage['output'] > 0 and response.token_usage['estimated']
