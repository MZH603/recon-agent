"""Real loopback bridge and durable runtime integration, no external model/tools."""
import asyncio
import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def fresh_logger_console(monkeypatch):
    monkeypatch.setattr('utils.logger._console',None)
    monkeypatch.setattr('utils.logger._stderr_mode',False)


def test_context_metrics_are_forwarded_live_and_in_saved_state():
    from cli.tui_session import TuiProgress, display_state
    from gate.scan_gate import ScanGate
    class Sink:
        def __init__(self): self.events = []
        def emit(self, event): self.events.append(event)
    sink = Sink()
    progress = TuiProgress(sink)
    metrics = {'context_tokens': 45000, 'context_capacity': 100000, 'context_trigger_tokens': 70000,
               'context_before_tokens': 78000, 'context_saved_tokens': 33000, 'context_compactions': 2,
               'context_compressed': True, 'context_limited': False, 'context_estimated': True}
    progress({'kind': 'context', **metrics})
    assert sink.events[0] == {'type': 'context', **metrics}
    assert not any(event['type'] == 'note' for event in sink.events), 'context is displayed once in the panel'
    state = display_state({'status': 'running', 'used_tokens': 900000, **metrics}, ScanGate('example.com'), progress)
    assert {key: state[key] for key in metrics} == metrics
    unknown = display_state({}, ScanGate('example.com'), progress)
    assert unknown.get('context_tokens') is None, 'unknown context must not be presented as zero'


@pytest.mark.parametrize('protocol', ['content', 'native', 'xml'])
def test_real_openai_sse_reaches_pi_before_server_finishes(tmp_path, monkeypatch, protocol):
    """Actual LiteLLM HTTP decoding, graph and IPC, with the server held mid-response."""
    from cli.tui_bridge import TuiBridge
    from cli.tui_session import serve_runtime
    from core.llm import LLMService
    from efficiency.budget_guard import BudgetGuard
    from model.litellm_adapter import LiteLLMAdapter
    from tests.unit.test_session_graph import fixture
    monkeypatch.setenv('LITELLM_LOCAL_MODEL_COST_MAP', 'True')

    async def scenario():
        release = asyncio.Event()
        release_reasoning = asyncio.Event()
        requests, errors = [], []
        first, second = '首段中文😀', '后段增量'

        async def handle(reader, writer):
            try:
                headers = await reader.readuntil(b'\r\n\r\n')
                size = int(next(line.split(b':', 1)[1] for line in headers.split(b'\r\n')
                                if line.lower().startswith(b'content-length:')))
                requests.append(json.loads(await reader.readexactly(size)))
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n')

                async def send(delta, finish=None):
                    value = {'id': 'local', 'object': 'chat.completion.chunk', 'created': 1,
                             'model': 'deepseek-flash', 'choices': [
                                 {'index': 0, 'delta': delta, 'finish_reason': finish}]}
                    if finish:
                        value['usage'] = {'prompt_tokens': 10, 'completion_tokens': 20, 'total_tokens': 30}
                    writer.write(('data: ' + json.dumps(value, ensure_ascii=False) + '\n\n').encode())
                    await writer.drain()

                await send({'reasoning_content': 'PRIVATE_INTERNAL_REASONING'})
                await release_reasoning.wait()
                if protocol == 'native':
                    await send({'tool_calls': [{'index': 0, 'id': 'call-local', 'type': 'function',
                        'function': {'name': 'ask_user', 'arguments': '{"question":"' + first}}]})
                elif protocol == 'xml':
                    await send({'content': '<tool_call><tool_name>ask_user</tool_name><parameters><question>' + first})
                else:
                    await send({'content': first})
                await release.wait()  # Cannot complete until Pi has received the first text.
                if protocol == 'native':
                    await send({'tool_calls': [{'index': 0, 'function': {'arguments': second + '"}'}}]})
                elif protocol == 'xml':
                    await send({'content': second + '</question></parameters></tool_call>'})
                else:
                    await send({'content': second+'\n<task_complete/>'})
                await send({}, 'tool_calls' if protocol == 'native' else 'stop')
                writer.write(b'data: [DONE]\n\n')
                await writer.drain()
            except Exception as exc:
                errors.append(exc)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        llm = LLMService.__new__(LLMService)
        llm.guard = BudgetGuard()
        llm.provider = LiteLLMAdapter('openai/deepseek-flash',
            api_base=f'http://127.0.0.1:{port}/v1', api_key='local-fixture', max_retries=0, timeout=20)
        runtime, tool, gate = fixture(tmp_path, llm)
        task, writer = None, None
        try:
            async with runtime, TuiBridge() as bridge:
                reader, writer = await asyncio.open_connection('127.0.0.1', bridge.port)
                writer.write((json.dumps({'type': 'hello', 'token': bridge.token}) + '\n').encode())
                await writer.drain()
                await bridge.wait_connected()
                task = asyncio.create_task(serve_runtime(runtime, gate, bridge))

                async def until(predicate):
                    while True:
                        event = json.loads(await asyncio.wait_for(reader.readline(), 15))
                        assert 'PRIVATE_INTERNAL_REASONING' not in json.dumps(event)
                        if predicate(event):
                            return event

                await until(lambda event: event['type'] == 'state')
                writer.write(b'{"type":"input","text":"inspect"}\n')
                await writer.drain()
                thinking = await until(lambda event: event['type'] == 'activity' and '思考中' in event['text'])
                assert 'PRIVATE' not in thinking['text'] and not release_reasoning.is_set()
                release_reasoning.set()
                preview = await until(lambda event: event['type'] == 'preview')
                assert preview['text'] == first
                assert not release.is_set() and not task.done() and tool.calls == 0
                assert requests[0]['stream'] is True
                release.set()
                await until(lambda event: event['type'] == 'preview' and event['text'].strip() == first + second)
                final = await until(lambda event: event['type'] == 'state')
                assert final['status'] == ('completed' if protocol=='content' else 'paused')
                assert (await runtime.state())['messages'][-1]['reasoning_content'] == 'PRIVATE_INTERNAL_REASONING'
                writer.write(b'{"type":"input","text":"continue"}\n')
                await writer.drain()
                await until(lambda event: event['type'] == 'state')
                previous = [message for message in requests[1]['messages'] if message['role'] == 'assistant']
                assert previous[-1]['reasoning_content'] == 'PRIVATE_INTERNAL_REASONING'
                writer.write(b'{"type":"quit"}\n')
                await writer.drain()
                assert await asyncio.wait_for(task, 3) == 0
                assert errors == [] and tool.calls == 0
        finally:
            release_reasoning.set()
            release.set()
            if task and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if writer:
                writer.close()
                await writer.wait_closed()
            server.close()
            await server.wait_closed()
    asyncio.run(scenario())


def test_loopback_auth_split_unicode_and_command_boundary():
    from cli.tui_bridge import TuiBridge, ProtocolError, child_environment
    async def scenario():
        async with TuiBridge() as bridge:
            badr, badw = await asyncio.open_connection('127.0.0.1', bridge.port)
            badw.write(b'{"type":"hello","token":"wrong"}\n')
            await badw.drain()
            assert await badr.read() == b''
            badw.close()
            reader, writer = await asyncio.open_connection('127.0.0.1', bridge.port)
            writer.write((json.dumps({'type':'hello', 'token':bridge.token})+'\n').encode())
            await writer.drain()
            await bridge.wait_connected()
            frame = json.dumps({'type':'input','text':'中文问题'},ensure_ascii=False).encode()+b'\n'
            for byte in frame:
                writer.write(bytes([byte]))
                await writer.drain()
            assert await bridge.receive() == {'type':'input','text':'中文问题'}
            await bridge.send({'type':'note','text':'逐段'})
            assert json.loads(await reader.readline())['text'] == '逐段'
            writer.write(b'{"type":"input","text":"test","is_tty":true}\n')
            await writer.drain()
            with pytest.raises(ProtocolError):
                await bridge.receive()
            writer.close()
            await writer.wait_closed()
    asyncio.run(scenario())
    env=child_environment(1234,'secret',{'PATH':'p','TERM':'x','RECON_API_KEY':'k','DEEPSEEK_API_KEY':'k','CUSTOM_API_KEY':'k','RECON_MAX_TOKENS':'999'})
    assert env['PATH']=='p' and env['RECON_TUI_TOKEN']=='secret'
    assert not any('API_KEY' in key or key=='RECON_MAX_TOKENS' for key in env)


@pytest.mark.parametrize('frame',[b'{broken}\n',b'{"type":"gate","level":2}\n',b'x'*65537+b'\n'],ids=['malformed','unknown','oversized'])
def test_malformed_unknown_and_oversized_frames_disconnect(frame):
    from cli.tui_bridge import TuiBridge, ProtocolError
    async def scenario():
        async with TuiBridge() as bridge:
            _, writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write((json.dumps({'type':'hello','token':bridge.token})+'\n').encode())
            await writer.drain()
            await bridge.wait_connected()
            writer.write(frame)
            await writer.drain()
            with pytest.raises(ProtocolError):
                await bridge.receive()
            writer.close()
    asyncio.run(scenario())


def test_idle_pending_resume_and_streamed_dedup(tmp_path,monkeypatch):
    from cli.tui_session import serve_runtime
    from cli.tui_bridge import TuiBridge
    from tests.unit.test_session_graph import fixture, ScriptedLLM, response
    from model.base import StreamEvent
    calls=[]
    class StreamLLM(ScriptedLLM):
        async def complete_stream(self,messages,tools,on_delta):
            calls.append(1)
            on_delta(StreamEvent(kind='tool',index=0,name='ask_user',arguments='{"question":"你想'))
            await asyncio.sleep(.05)
            on_delta(StreamEvent(kind='tool',index=0,arguments='查询什么？"}'))
            return await self.complete(messages,tools)
    async def scenario():
        runtime,_,gate=fixture(tmp_path,StreamLLM(response('ask_user',{'question':'你想查询什么？'}),response('finish_task',{'answer':'完成','clarification_only':True})))
        async with runtime,TuiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write((json.dumps({'type':'hello','token':bridge.token})+'\n').encode());await writer.drain()
            await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            async def until(kind):
                events=[]
                while True:
                    event=json.loads(await asyncio.wait_for(reader.readline(),3));events.append(event)
                    if event['type']==kind:return events
            await until('state')
            assert calls==[]
            writer.write(b'{"type":"input","text":"inspect"}\n');await writer.drain()
            events=await until('state')
            assert any(e['type']=='preview' and '你想' in e['text'] for e in events)
            assert events[-1]['pending']['kind']=='ask_user'
            assert gate.current_level()==0
            writer.write(b'{"type":"input","text":"continue"}\n');await writer.drain()
            await until('state')
            writer.write(b'{"type":"quit"}\n');await writer.drain()
            assert await task==0
            writer.close()
    asyncio.run(scenario())


def test_long_preview_keeps_tail_and_no_final_duplicate():
    from cli.tui_session import TuiProgress,display_state
    from model.base import StreamEvent
    from gate.scan_gate import ScanGate
    class Sink:
        events=[]
        def emit(self,event):self.events.append(event)
    sink=Sink();progress=TuiProgress(sink)
    answer='长中文 '*7000+'尾标记'
    progress({'kind':'model_start'})
    progress({'kind':'delta','delta':StreamEvent(kind='content',content=answer)})
    progress({'kind':'model_end','success':True})
    chunks=[e for e in sink.events if e['type']=='preview']
    assert all(len(json.dumps(e,ensure_ascii=False).encode())<65536 for e in chunks)
    assert ''.join(e['text'] for e in sorted(chunks,key=lambda e:e.get('offset',0)))==answer
    assert 'answer' not in display_state({'answer':answer},ScanGate('example.com'),progress)


@pytest.mark.parametrize('token',['坏令牌','\ud800'],ids=['unicode','surrogate'])
def test_unicode_bad_auth_is_quiet_and_listener_survives(token):
    from cli.tui_bridge import TuiBridge
    async def scenario():
        errors=[];asyncio.get_running_loop().set_exception_handler(lambda loop,ctx:errors.append(ctx))
        async with TuiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':token}).encode()+b'\n');await writer.drain()
            assert await asyncio.wait_for(reader.read(),2)==b''
            writer.close()
        assert not errors
    asyncio.run(scenario())


def test_deep_json_handshake_is_quietly_rejected_and_listener_stays_open():
    from cli.tui_bridge import TuiBridge
    async def scenario():
        errors=[];asyncio.get_running_loop().set_exception_handler(lambda loop,ctx:errors.append(ctx))
        async with TuiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(b'['*20000+b'0'+b']'*20000+b'\n');await writer.drain()
            assert await asyncio.wait_for(reader.read(),2)==b''
            writer.close()
            assert bridge.server.is_serving()
        assert not errors
    asyncio.run(scenario())


def test_emoji_options_and_long_unstreamed_dialogue_fit_transport_frames():
    from cli.tui_session import TuiProgress,display_state
    from gate.scan_gate import ScanGate
    class Sink:
        def __init__(self):self.events=[]
        def emit(self,event):self.events.append(event)
    sink=Sink();progress=TuiProgress(sink)
    question='中文😀'*10000+'问题尾部'
    state={'status':'paused','pending':{'kind':'ask_user','question':question,'options':['😀'*1000 for _ in range(20)]}}
    event=display_state(state,ScanGate('example.com'),progress)
    assert len(json.dumps(event,ensure_ascii=False).encode())<65536
    assert ''.join(e['text'] for e in sink.events if e['type']=='preview')==question
    assert any('…' in text for text in event['pending']['options'])


@pytest.mark.parametrize('ending',['stop','abort','cancel','disconnect'])
def test_active_cancel_disconnect_usage_and_ownership(tmp_path,ending):
    from cli.tui_session import serve_runtime
    from cli.tui_bridge import TuiBridge
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    from model.base import StreamEvent
    async def scenario():
        started=asyncio.Event();cancelled=asyncio.Event()
        class Waiting(ScriptedLLM):
            async def complete_stream(self,messages,tools,on_delta):
                on_delta(StreamEvent(kind='content',content='部分中文'))
                started.set()
                try:await asyncio.Event().wait()
                finally:self.guard.register(5,7);cancelled.set()
        runtime,tool,gate=fixture(tmp_path,Waiting())
        async with runtime,TuiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            await reader.readline()
            writer.write(b'{"type":"input","text":"inspect"}\n');await writer.drain();await started.wait()
            if ending=='disconnect':writer.close();await writer.wait_closed()
            else:
                writer.write(json.dumps({'type':ending,'exit':True} if ending=='cancel' else {'type':ending}).encode()+b'\n');await writer.drain()
                if ending in ('stop','abort'):
                    while json.loads(await reader.readline())['type']!='state':pass
                    writer.write(b'{"type":"quit"}\n');await writer.drain()
            assert await asyncio.wait_for(task,3)==(130 if ending=='cancel' else 2 if ending=='disconnect' else 0)
            assert cancelled.is_set() and tool.calls==0
            assert (await runtime.state())['used_tokens']>=12
            writer.close()
        restored,_,_=fixture(tmp_path,ScriptedLLM())
        async with restored:
            assert (await restored.state())['used_tokens']>=12
    asyncio.run(scenario())


def test_log_capture_restores_cached_console_and_streams(capsys):
    from cli.tui_session import capture_logs
    from utils import logger
    class Sink:
        events=[]
        def emit(self,event):self.events.append(event)
    previous=logger.console();sink=Sink()
    with capture_logs(sink):
        logger.info('日志消息');print('普通消息')
    assert logger._console is previous
    assert {'日志消息','普通消息'} <= {e['text'].removeprefix('[*] ') for e in sink.events}
    assert '日志消息' not in capsys.readouterr().out


@pytest.mark.parametrize('protocol', ['content', 'xml'])
def test_real_node_frontend_disconnection_cancels_graph_and_preserves_usage(tmp_path, protocol):
    from cli.tui_bridge import TuiBridge,TUI_DIR,child_environment
    from cli.tui_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    from model.base import StreamEvent
    async def scenario():
        cancelled=asyncio.Event()
        class Waiting(ScriptedLLM):
            async def complete_stream(self,messages,tools,on_delta):
                prefix = '<tool_call><tool_name>ask_user</tool_name><parameters><question>' if protocol == 'xml' else ''
                on_delta(StreamEvent(kind='content',content=prefix+'首段中文😀'))
                await asyncio.sleep(.15)
                on_delta(StreamEvent(kind='content',content='后段增量'))
                try:await asyncio.Event().wait()
                finally:self.guard.register(11,13);cancelled.set()
        runtime,tool,gate=fixture(tmp_path,Waiting())
        async with runtime,TuiBridge() as bridge:
            child=await asyncio.create_subprocess_exec('node',str(Path(__file__).resolve().parents[1] / 'tui/fixture.mjs'),cwd=TUI_DIR,
                env=child_environment(bridge.port,bridge.token),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            try:
                await bridge.wait_connected()
                task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
                stdout,stderr=await asyncio.wait_for(child.communicate(),5)
                assert child.returncode==0,stderr.decode()
                evidence=json.loads(stdout)
                assert evidence['firstRendered'] and evidence['incremental'] and evidence['loader'] and evidence['restored']
                assert await asyncio.wait_for(task,3)==2
                assert cancelled.is_set() and tool.calls==0
            finally:
                if child.returncode is None:child.kill();await child.wait()
        restored,_,_=fixture(tmp_path,ScriptedLLM())
        async with restored:
            state=await restored.state()
            assert state['used_tokens']>=24 and state['pending']['kind']=='recovery'
    asyncio.run(scenario())


@pytest.mark.parametrize('mode,tty_out,batch,available,expected',[
    ('auto',True,False,True,'tui'),('rich',True,False,True,'rich'),
    ('auto',True,False,False,'rich'),('tui',True,False,False,'error'),
    ('tui',False,False,True,'rich'),('auto',True,True,True,'rich'),
    ('tui',True,False,True,'tui'),('pi',True,False,True,'tui'),
    ('pi',True,False,False,'error')])
def test_cli_ui_selection_keeps_original_tty_and_runner_api(monkeypatch,mode,tty_out,batch,available,expected):
    from typer.testing import CliRunner
    from cli.main import app
    captured=[]
    monkeypatch.setenv('TERM','xterm-256color')
    async def rich(**kwargs):captured.append(('rich',kwargs));return 0
    async def tui(**kwargs):captured.append(('tui',kwargs));return 0
    monkeypatch.setattr('cli.session.run_session',rich)
    monkeypatch.setattr('cli.tui_session.run_tui_session',tui)
    monkeypatch.setattr('cli.tui_bridge.tui_available',lambda:(available,'fixture missing dependency'))
    # CliRunner installs capture streams, so patch their classes during the command.
    import cli.main as main
    original=main._settings_with
    def settings(*args):
        monkeypatch.setattr(main.sys.stdin,'isatty',lambda:True)
        monkeypatch.setattr(main.sys.stdout,'isatty',lambda:tty_out)
        return original(*args)
    monkeypatch.setattr(main,'_settings_with',settings)
    result=CliRunner().invoke(app,['--session','-t','example.com','--authorized','--ui',mode]+(['--batch'] if batch else []))
    assert result.exit_code==(2 if expected=='error' else 0),result.output
    if expected!='error':
        assert captured[0][0]==expected and captured[0][1]['is_tty'] is True
        assert 'auto_confirm' not in captured[0][1]
    if not available:assert 'TUI' in result.output


@pytest.mark.parametrize('kind',[{},[],None,1],ids=['object','array','null','number'])
def test_command_type_is_validated_before_mapping_lookup(kind):
    from cli.tui_bridge import TuiBridge,ProtocolError
    async def scenario():
        async with TuiBridge() as bridge:
            _,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            writer.write(json.dumps({'type':kind}).encode()+b'\n');await writer.drain()
            with pytest.raises(ProtocolError):await bridge.receive()
            assert bridge.disconnected.is_set()
            writer.close()
    asyncio.run(scenario())


def test_auth_pending_reply_is_backend_owned_and_exact_codes_remain_independent(tmp_path):
    from cli.tui_bridge import TuiBridge
    from cli.tui_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM,response
    async def scenario():
        llm=ScriptedLLM(response('fixture',{'target':'example.com'}),response('ask_user',{'question':'Next?'}))
        runtime,tool,gate=fixture(tmp_path,llm,level=2)
        async with runtime,TuiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            async def state():
                while True:
                    event=json.loads(await asyncio.wait_for(reader.readline(),3))
                    if event['type']=='state':return event
            await state()
            for text in ['inspect','y','continue','CONFIRM 2','example.com','I UNDERSTAND AND AUTHORIZE']:
                writer.write(json.dumps({'type':'input','text':text}).encode()+b'\n');await writer.drain()
                current=await state();assert tool.calls==0
                assert current['pending']['question'], 'Every fresh authorization prompt must be visible'
                assert current['pending'].get('interrupt_id'), 'Pending identity must survive the bridge'
                if text=='continue':
                    assert current['pending']['kind']=='authorization'
                    assert 'CONFIRM 2' in current['pending']['question']
            assert gate.current_level()==2
            writer.write(b'{"type":"input","text":"yes"}\n');await writer.drain();await state()
            assert tool.calls==1
            writer.write(b'{"type":"quit"}\n');await writer.drain();await task;writer.close()
    asyncio.run(scenario())


def test_slow_ui_queue_is_bounded_and_cancels_active_graph(tmp_path):
    from cli.tui_bridge import TuiBridge
    from cli.tui_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    async def scenario():
        started=asyncio.Event();cancelled=asyncio.Event()
        class Waiting(ScriptedLLM):
            async def complete(self,*args):
                started.set()
                try:await asyncio.Event().wait()
                finally:self.guard.register(2,3);cancelled.set()
        runtime,tool,gate=fixture(tmp_path,Waiting())
        async with runtime,TuiBridge() as bridge:
            _,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            writer.write(b'{"type":"input","text":"inspect"}\n');await writer.drain();await started.wait()
            for _ in range(1000):bridge.emit({'type':'note','text':'slow '*1000})
            assert bridge.queue.qsize()<=128 and bridge.disconnected.is_set()
            assert await asyncio.wait_for(task,3)==2
            assert cancelled.is_set() and tool.calls==0 and (await runtime.state())['used_tokens']>=5
            writer.close()
    asyncio.run(scenario())


def test_installed_pi_probe_and_old_node_rejected(monkeypatch):
    from cli.tui_bridge import tui_available
    from types import SimpleNamespace
    assert tui_available()==(True,'')
    monkeypatch.setattr('cli.tui_bridge.subprocess.run',lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout='20.0.0'))
    assert not tui_available()[0] and '22.19.0' in tui_available()[1]


def test_authenticated_bridge_refuses_a_second_frontend_and_releases_port():
    from cli.tui_bridge import TuiBridge
    async def scenario():
        async with TuiBridge() as bridge:
            port=bridge.port
            _,writer=await asyncio.open_connection('127.0.0.1',port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            assert not bridge.server.is_serving()
            with pytest.raises(OSError):await asyncio.open_connection('127.0.0.1',port)
            writer.close()
        server=await asyncio.start_server(lambda r,w:w.close(),'127.0.0.1',port)
        server.close();await server.wait_closed()
    asyncio.run(scenario())


def test_protocol_error_returns_failure_after_graph_cleanup(tmp_path):
    from cli.tui_bridge import TuiBridge
    from cli.tui_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    async def scenario():
        runtime,_,gate=fixture(tmp_path,ScriptedLLM())
        async with runtime,TuiBridge() as bridge:
            _,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            writer.write(b'{broken}\n');await writer.drain()
            assert await asyncio.wait_for(task,3)==2
            writer.close()
    asyncio.run(scenario())


def test_hung_child_gets_force_killed_after_graceful_deadline():
    from cli import tui_session
    async def scenario():
        class Hung:
            returncode=None
            def __init__(self):self.done=asyncio.Event();self.killed=False
            async def wait(self):await self.done.wait();return self.returncode
            def terminate(self):raise AssertionError('catchable terminate is insufficient')
            def kill(self):self.killed=True;self.returncode=-9;self.done.set()
        child=Hung()
        await asyncio.wait_for(tui_session.close_child(child,timeout=.01),1)
        assert child.killed and child.returncode==-9
    asyncio.run(scenario())


def test_runner_reports_disconnect_only_after_child_and_log_capture_restore(tmp_path,monkeypatch):
    from cli.tui_session import run_tui_session
    from utils.config import Settings
    import sys
    original_out=sys.stdout;notices=[]
    monkeypatch.setattr('platforms.paths.get_config_dir',lambda:tmp_path)
    monkeypatch.setattr('cli.tui_session.tui_available',lambda:(True,''))
    async def scenario():
        class Child:
            returncode=None
            def __init__(self):self.done=asyncio.Event()
            async def wait(self):await self.done.wait();return self.returncode
            def kill(self):self.returncode=-9;self.done.set()
        child=Child()
        async def spawn(*args,env):
            async def frontend():
                reader,writer=await asyncio.open_connection('127.0.0.1',int(env['RECON_TUI_PORT']))
                writer.write(json.dumps({'type':'hello','token':env['RECON_TUI_TOKEN']}).encode()+b'\n');await writer.drain()
                while json.loads(await reader.readline())['type']!='state':pass
                writer.write(b'{broken}\n');await writer.drain()
                await reader.read();writer.close();await writer.wait_closed()
                child.returncode=1;child.done.set()
            child.frontend=asyncio.create_task(frontend())
            return child
        monkeypatch.setattr('cli.tui_session.asyncio.create_subprocess_exec',spawn)
        def warn(message):
            assert child.returncode is not None and sys.stdout is original_out
            notices.append(message)
        monkeypatch.setattr('utils.logger.warn',warn)
        def forbidden(*args):raise AssertionError('idle constructed model')
        result=await run_tui_session('example.com',Settings(),False,True,0,None,'json',str(tmp_path),
            session_id='frontend-failed',llm_factory=forbidden)
        assert result==2
        await child.frontend
    asyncio.run(scenario())
    assert len(notices)==1 and '--resume frontend-failed' in notices[0]


def test_saved_plan_is_visible_on_initial_state_and_status_without_model_calls(tmp_path):
    from cli.tui_bridge import TuiBridge
    from cli.tui_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    async def scenario():
        llm=ScriptedLLM();runtime,tool,gate=fixture(tmp_path,llm)
        async with runtime,TuiBridge() as bridge:
            await runtime.graph.aupdate_state(runtime.config,{'plan':'先查询 DNS，再总结来源。'})
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            initial=json.loads(await reader.readline())
            assert initial['plan']=='先查询 DNS，再总结来源。'
            writer.write(b'{"type":"status"}\n');await writer.drain()
            status=json.loads(await reader.readline())
            assert status['plan']==initial['plan'] and llm.calls==tool.calls==0
            writer.write(b'{"type":"quit"}\n');await writer.drain();assert await task==0;writer.close()
    asyncio.run(scenario())


def test_long_unicode_saved_plan_has_explicit_label_and_bounded_full_segments():
    from cli.tui_session import TuiProgress,display_state
    from gate.scan_gate import ScanGate
    class Sink:
        def __init__(self):self.events=[]
        def emit(self,event):self.events.append(event)
    sink=Sink();progress=TuiProgress(sink);plan='中文😀计划 '*5000+'计划尾部'
    state=display_state({'plan':plan},ScanGate('example.com'),progress)
    assert len(json.dumps(state,ensure_ascii=False).encode())<65536
    assert any(e['type']=='note' and '计划' in e['text'] for e in sink.events)
    assert ''.join(e['text'] for e in sink.events if e['type']=='preview')==plan
    assert all(len(json.dumps(e,ensure_ascii=False).encode())<65536 for e in sink.events)
