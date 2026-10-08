"""Offline rendering and runtime observation contracts."""
import asyncio
from io import StringIO

import pytest
from rich.console import Console
from model.base import StreamEvent, LLMResponse, NormalizedToolCall, ModelUnavailable


def renderer(tty=False):
    from cli.progress import SessionProgress
    output=StringIO()
    return SessionProgress(console=Console(file=output, force_terminal=tty, width=100, color_system=None,
                                          _environ={'TERM':'xterm-256color'}),
                           is_tty=tty), output


def test_plain_incremental_text_is_visible_before_end_no_ansi_and_no_duplicate():
    progress, out=renderer()
    with progress:
        progress({'kind':'model_start'})
        progress({'kind':'delta', 'delta':StreamEvent('content', content='hello ')})
        assert 'hello ' in out.getvalue()
        progress({'kind':'delta', 'delta':StreamEvent('content', content='world')})
        progress({'kind':'model_end', 'success':True})
    assert out.getvalue().count('hello world') == 1
    assert '\x1b' not in out.getvalue()
    assert progress.was_shown('hello world')


def test_native_control_text_streams_across_json_unicode_escapes():
    progress, out=renderer()
    with progress:
        progress({'kind':'model_start'})
        progress({'kind':'delta', 'delta':StreamEvent('tool', index=1, name='finish_task',
                                                    arguments='{"answer":"你\\u')})
        assert '你' in out.getvalue()
        progress({'kind':'delta', 'delta':StreamEvent('tool', index=1, arguments='597d\\n[red]literal')})
        assert '你好\n[red]literal' in out.getvalue()
        progress({'kind':'delta', 'delta':StreamEvent('tool', index=0, name='scan', arguments='{"secret":"hidden"}')})
        progress({'kind':'delta', 'delta':StreamEvent('tool', index=1, arguments='", "evidence":[]}')})
        progress({'kind':'model_end', 'success':True})
    assert 'secret' not in out.getvalue() and 'evidence' not in out.getvalue()
    assert 'answer' not in out.getvalue() and 'hidden' not in out.getvalue()


def test_split_xml_reasoning_and_terminal_controls_are_hidden():
    progress, out=renderer()
    with progress:
        progress({'kind':'model_start'})
        for text in ['safe<to', 'ol_call><tool_name>scan</tool_name>SECRET', '</tool_call>',
                     '<thi', 'nk>PRIVATE</think>', '\x1b[', '31m[red]literal\x1b[0m\x00\u202eend']:
            progress({'kind':'delta', 'delta':StreamEvent('content', content=text)})
        progress({'kind':'model_end', 'success':True})
    value=out.getvalue()
    assert 'safe[red]literalend' in value
    assert all(s not in value for s in ('SECRET', 'PRIVATE', 'tool_call', '\x1b', '\x00', '\u202e'))


@pytest.mark.parametrize('name,field', [('finish_task', 'answer'), ('ask_user', 'question')])
def test_xml_dialogue_is_visible_before_control_call_is_complete(name, field):
    progress, out = renderer()
    with progress:
        progress({'kind': 'model_start'})
        for piece in ['<tool_', 'call><tool_name>', name,
                      '</tool_name><parameters><' + field + '>首段中文😀']:
            progress({'kind': 'delta', 'delta': StreamEvent('content', content=piece)})
        assert '首段中文😀' in out.getvalue(), 'XML dialogue must appear before the final chunk'
        for piece in ['后段 &am', 'p; 文本</' + field + '><evidence>SECRET</evidence>',
                      '</parameters></tool_call>']:
            progress({'kind': 'delta', 'delta': StreamEvent('content', content=piece)})
        progress({'kind': 'model_end', 'success': True})
    assert progress.was_shown('首段中文😀后段 & 文本')
    assert 'SECRET' not in out.getvalue() and 'tool_call' not in out.getvalue()


def test_xml_preview_keeps_non_dialogue_and_nested_fields_hidden():
    from cli.progress import xml_dialogue
    raw = ('<tool_call><tool_name>scan</tool_name><parameters><answer>SECRET</answer></parameters></tool_call>'
           '<tool_call><tool_name>ask_user</tool_name><parameters><other><question>SECRET</question></other>'
           '<question>Visible<think>PRIVATE</think> &amp; &#x1f600;</question>'
           '<options>SECRET</options></parameters></tool_call>')
    assert list(xml_dialogue(raw)) == [(0, ''), (1, 'Visible & 😀')]


def test_xml_preview_survives_every_character_boundary():
    from cli.progress import xml_dialogue
    raw = '<tool_call><tool_name>ask_user</tool_name><parameters><question>你好 &amp; &#x1f600;</question></parameters></tool_call>'
    previous = ''
    for position in range(len(raw) + 1):
        values = list(xml_dialogue(raw[:position]))
        current = values[0][1] if values else ''
        assert current.startswith(previous)
        previous = current
    assert previous == '你好 & 😀'


@pytest.mark.parametrize('closing', ['', '</think>'])
def test_xml_calls_inside_reasoning_are_not_previewed(closing):
    from cli.progress import xml_dialogue
    raw = '<think><tool_call><tool_name>ask_user</tool_name><parameters><question>PRIVATE</question></parameters></tool_call>' + closing
    assert list(xml_dialogue(raw)) == []


@pytest.mark.parametrize('text',[
    '条件：status < 500，继续。',
    '代码：`if count < limit: retry()`，然后继续。',
    '多个比较：x < 2 且 y < 4，完成。',
])
def test_ordinary_less_than_comparisons_and_code_preserve_text(text):
    from cli.progress import visible_content
    assert visible_content(text)==text


def test_less_than_chunk_releases_once_reserved_tag_is_impossible():
    progress,out=renderer()
    with progress:
        progress({'kind':'model_start'})
        progress({'kind':'delta','delta':StreamEvent('content',content='条件：status <')})
        progress({'kind':'delta','delta':StreamEvent('content',content=' 500，继续。')})
        assert '条件：status < 500，继续。' in out.getvalue()
        progress({'kind':'delta','delta':StreamEvent('content',content='<thi')})
        assert '<thi' not in out.getvalue()
        progress({'kind':'delta','delta':StreamEvent('content',content='nk>PRIVATE</think>结束。')})
        progress({'kind':'model_end','success':True})
    assert 'PRIVATE' not in out.getvalue() and '结束。' in out.getvalue()


def test_ordinary_comparison_before_reserved_tag_does_not_leak_reasoning():
    from cli.progress import visible_content
    assert visible_content('status < 500<think>PRIVATE</think>继续。')=='status < 500继续。'


def test_tty_live_spinner_elapsed_and_interrupt_cleanup():
    progress, out=renderer(True)
    with progress:
        assert progress.live.is_started
        progress({'kind':'model_start'})
        progress({'kind':'delta', 'delta':StreamEvent('content', content='partial')})
        progress.live.refresh()
        progress({'kind':'model_end', 'success':False})
    assert not progress.live.is_started
    assert '等待模型' in out.getvalue() and '0.' in out.getvalue()
    assert '未完成' in out.getvalue()


def test_runtime_observation_previews_control_and_only_authorized_tools(tmp_path):
    from tests.unit.test_session_graph import ScriptedLLM, response, fixture
    class Streaming(ScriptedLLM):
        async def complete_stream(self, messages, tools, on_delta):
            result=await self.complete(messages, tools)
            for call in result.tool_calls:
                on_delta(StreamEvent('tool', name=call.name, arguments='{"question":"Next?"}'))
            return result
    async def scenario():
        events=[]
        llm=Streaming(response('fixture', {'target':'example.com'}), response('ask_user', {'question':'Next?'}))
        runtime, tool, _=fixture(tmp_path, llm, level=1, on_event=events.append)
        async with runtime:
            state=await runtime.submit('inspect')
            assert not tool.calls and not any(e['kind']=='tool_start' for e in events)
            state=await runtime.resume('yes')
            assert tool.calls == 1 and state['pending']['question']=='Next?'
            kinds=[e['kind'] for e in events]
            assert kinds.index('model_start') < kinds.index('delta') < kinds.index('model_end')
            assert kinds.index('tool_start') < kinds.index('tool_end')
            assert 'pause' in kinds
            assert all('delta' not in str(e) for e in state['events'])
    asyncio.run(scenario())


@pytest.mark.parametrize('cancel', [False, True])
def test_partial_runtime_usage_survives_reopen_without_executing_tools(tmp_path, cancel):
    from tests.unit.test_session_graph import ScriptedLLM, fixture
    from langgraph.errors import NodeCancelledError
    class Broken(ScriptedLLM):
        async def complete_stream(self, messages, tools, on_delta):
            on_delta(StreamEvent('tool', name='fixture', arguments='{"target":"example'))
            if cancel:
                raise asyncio.CancelledError
            raise ModelUnavailable('stream lost')
    async def scenario():
        runtime, tool, _=fixture(tmp_path, Broken(), on_event=lambda e: None)
        async with runtime:
            if cancel:
                with pytest.raises((asyncio.CancelledError, NodeCancelledError)):
                    await runtime.submit('inspect')
            else:
                state=await runtime.submit('inspect')
                assert state['pending']['kind']=='model_unavailable'
            state=await runtime.state()
            assert state['used_tokens'] > 0 and state['cost_unknown_calls'] == 1
            assert tool.calls == 0
        restored, _, _=fixture(tmp_path, ScriptedLLM())
        async with restored:
            state=await restored.state()
            assert state['used_tokens'] > 0 and restored.guard.used_tokens == state['used_tokens']
    asyncio.run(scenario())


def test_observer_failure_does_not_change_result_and_cancellation_is_not_swallowed(tmp_path):
    from tests.unit.test_session_graph import ScriptedLLM, response, fixture
    from langgraph.errors import NodeCancelledError
    async def scenario():
        def broken(event):
            raise ValueError('UI failed')
        runtime, _, _=fixture(tmp_path, ScriptedLLM(response('ask_user', {'question':'Next?'})), on_event=broken)
        async with runtime:
            assert (await runtime.submit('inspect'))['pending']['kind']=='ask_user'
        def cancel(event):
            raise asyncio.CancelledError
        runtime, _, _=fixture(tmp_path/'cancel', ScriptedLLM(), on_event=cancel)
        async with runtime:
            with pytest.raises((asyncio.CancelledError, NodeCancelledError)):
                await runtime.submit('inspect')
    asyncio.run(scenario())


def test_long_tty_paragraph_commits_history_before_final():
    from rich.cells import cell_len
    progress, out=renderer(True)
    text='长段落中文及literal ' * 200 + 'VISIBLETAIL'
    with progress:
        progress({'kind':'model_start'})
        for offset in range(0, len(text), 41):
            progress({'kind':'delta', 'delta':StreamEvent('content', content=text[offset:offset+41])})
        assert cell_len(progress.line) <= progress.console.width
        assert 'VISIBLETAIL' in out.getvalue()
        assert progress.in_model
        progress({'kind':'model_end', 'success':True})
    assert progress.was_shown(text)


def test_cli_native_question_and_answer_are_visible_before_final_and_deduplicated(tmp_path, monkeypatch):
    from tests.unit.test_session_cli import run
    output=StringIO()
    monkeypatch.setattr('utils.logger._console', Console(file=output, force_terminal=False, width=160))
    class Native:
        def __init__(self, *args):
            self.calls=0
        async def complete(self, *args):
            raise AssertionError('stream bridge must be used')
        async def complete_stream(self, messages, tools, on_delta):
            self.calls += 1
            name, field, first, second = ('ask_user','question','Which ','topic?') if self.calls==1 else (
                'finish_task','answer','DNS ','explained')
            on_delta(StreamEvent('tool', name=name, arguments='{"'+field+'":"'+first))
            assert first in output.getvalue(), 'control text must appear before final response'
            await asyncio.sleep(0)
            on_delta(StreamEvent('tool', arguments=second+'"}'))
            return LLMResponse(tool_calls=[NormalizedToolCall(id='call', name=name, arguments={
                field:first+second, **({'clarification_only':True} if name=='finish_task' else {})})])
    assert run(tmp_path, monkeypatch, ['Explain','DNS','quit'], Native) == 0
    value=output.getvalue()
    assert value.count('Which topic?') == value.count('DNS explained') == 1
    assert '"question"' not in value and '"answer"' not in value


def test_model_end_callback_cancellation_cannot_erase_completed_usage(tmp_path):
    from tests.unit.test_session_graph import ScriptedLLM, response, fixture
    from langgraph.errors import NodeCancelledError
    class Unmetered(ScriptedLLM):
        async def complete(self, messages, tools=None):
            result=response('ask_user', {'question':'Next?'})
            result.token_usage={'input':10, 'output':5, 'cost':.01}
            return result
    async def scenario():
        def observer(event):
            if event['kind']=='model_end':
                raise asyncio.CancelledError
        runtime, _, _=fixture(tmp_path, Unmetered(), on_event=observer)
        async with runtime:
            with pytest.raises((asyncio.CancelledError, NodeCancelledError)):
                await runtime.submit('inspect')
            state=await runtime.state()
            assert state['used_tokens']==15 and state['used_cost']==.01
    asyncio.run(scenario())


def test_tool_start_observer_cancellation_restores_gate_and_clears_permit(tmp_path):
    from tests.unit.test_session_graph import ScriptedLLM, response, fixture
    from langgraph.errors import NodeCancelledError
    async def scenario():
        def observer(event):
            if event['kind']=='tool_start':
                raise asyncio.CancelledError
        runtime, tool, gate=fixture(tmp_path, ScriptedLLM(response('fixture', {'target':'example.com'})),
                                   on_event=observer)
        original=gate._prompt_fn
        async with runtime:
            with pytest.raises((asyncio.CancelledError, NodeCancelledError)):
                await runtime.submit('inspect')
            assert gate._prompt_fn is original
            assert runtime._permit is None
            assert tool.calls == 0
    asyncio.run(scenario())
