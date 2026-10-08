"""Real loopback bridge and durable runtime integration, no external model/tools."""
import asyncio
import importlib.util
import json

import pytest


@pytest.fixture(autouse=True)
def fresh_logger_console(monkeypatch):
    monkeypatch.setattr('utils.logger._console',None)
    monkeypatch.setattr('utils.logger._stderr_mode',False)


def test_pi_bridge_is_available():
    assert importlib.util.find_spec('cli.pi_bridge'), 'authenticated Pi bridge is missing'


def test_loopback_auth_split_unicode_and_command_boundary():
    from cli.pi_bridge import PiBridge, ProtocolError, child_environment
    async def scenario():
        async with PiBridge() as bridge:
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
    assert env['PATH']=='p' and env['RECON_PI_TOKEN']=='secret'
    assert not any('API_KEY' in key or key=='RECON_MAX_TOKENS' for key in env)


@pytest.mark.parametrize('frame',[b'{broken}\n',b'{"type":"gate","level":2}\n',b'x'*65537+b'\n'],ids=['malformed','unknown','oversized'])
def test_malformed_unknown_and_oversized_frames_disconnect(frame):
    from cli.pi_bridge import PiBridge, ProtocolError
    async def scenario():
        async with PiBridge() as bridge:
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
    from cli.pi_session import serve_runtime
    from cli.pi_bridge import PiBridge
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
        async with runtime,PiBridge() as bridge:
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
    from cli.pi_session import PiProgress,display_state
    from model.base import StreamEvent
    from gate.scan_gate import ScanGate
    class Sink:
        events=[]
        def emit(self,event):self.events.append(event)
    sink=Sink();progress=PiProgress(sink)
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
    from cli.pi_bridge import PiBridge
    async def scenario():
        errors=[];asyncio.get_running_loop().set_exception_handler(lambda loop,ctx:errors.append(ctx))
        async with PiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':token}).encode()+b'\n');await writer.drain()
            assert await asyncio.wait_for(reader.read(),2)==b''
            writer.close()
        assert not errors
    asyncio.run(scenario())


def test_deep_json_handshake_is_quietly_rejected_and_listener_stays_open():
    from cli.pi_bridge import PiBridge
    async def scenario():
        errors=[];asyncio.get_running_loop().set_exception_handler(lambda loop,ctx:errors.append(ctx))
        async with PiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(b'['*20000+b'0'+b']'*20000+b'\n');await writer.drain()
            assert await asyncio.wait_for(reader.read(),2)==b''
            writer.close()
            assert bridge.server.is_serving()
        assert not errors
    asyncio.run(scenario())


def test_emoji_options_and_long_unstreamed_dialogue_fit_transport_frames():
    from cli.pi_session import PiProgress,display_state
    from gate.scan_gate import ScanGate
    class Sink:
        def __init__(self):self.events=[]
        def emit(self,event):self.events.append(event)
    sink=Sink();progress=PiProgress(sink)
    question='中文😀'*10000+'问题尾部'
    state={'status':'paused','pending':{'kind':'ask_user','question':question,'options':['😀'*1000 for _ in range(20)]}}
    event=display_state(state,ScanGate('example.com'),progress)
    assert len(json.dumps(event,ensure_ascii=False).encode())<65536
    assert ''.join(e['text'] for e in sink.events if e['type']=='preview')==question
    assert any('…' in text for text in event['pending']['options'])


@pytest.mark.parametrize('ending',['stop','abort','cancel','disconnect'])
def test_active_cancel_disconnect_usage_and_ownership(tmp_path,ending):
    from cli.pi_session import serve_runtime
    from cli.pi_bridge import PiBridge
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
        async with runtime,PiBridge() as bridge:
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
            assert await asyncio.wait_for(task,3)==(130 if ending=='cancel' else 0)
            assert cancelled.is_set() and tool.calls==0
            assert (await runtime.state())['used_tokens']>=12
            writer.close()
        restored,_,_=fixture(tmp_path,ScriptedLLM())
        async with restored:
            assert (await restored.state())['used_tokens']>=12
    asyncio.run(scenario())


def test_log_capture_restores_cached_console_and_streams(capsys):
    from cli.pi_session import capture_logs
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


def test_real_node_frontend_disconnection_cancels_graph_and_preserves_usage(tmp_path):
    from cli.pi_bridge import PiBridge,PI_DIR,child_environment
    from cli.pi_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    from model.base import StreamEvent
    async def scenario():
        cancelled=asyncio.Event()
        class Waiting(ScriptedLLM):
            async def complete_stream(self,messages,tools,on_delta):
                on_delta(StreamEvent(kind='content',content='首段中文😀'))
                await asyncio.sleep(.15)
                on_delta(StreamEvent(kind='content',content='后段增量'))
                try:await asyncio.Event().wait()
                finally:self.guard.register(11,13);cancelled.set()
        runtime,tool,gate=fixture(tmp_path,Waiting())
        async with runtime,PiBridge() as bridge:
            child=await asyncio.create_subprocess_exec('node','fixture.mjs',cwd=PI_DIR,
                env=child_environment(bridge.port,bridge.token),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            try:
                await bridge.wait_connected()
                task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
                stdout,stderr=await asyncio.wait_for(child.communicate(),5)
                assert child.returncode==0,stderr.decode()
                evidence=json.loads(stdout)
                assert evidence['incremental'] and evidence['loader'] and evidence['restored']
                assert await asyncio.wait_for(task,3)==0
                assert cancelled.is_set() and tool.calls==0
            finally:
                if child.returncode is None:child.kill();await child.wait()
        restored,_,_=fixture(tmp_path,ScriptedLLM())
        async with restored:
            state=await restored.state()
            assert state['used_tokens']>=24 and state['pending']['kind']=='recovery'
    asyncio.run(scenario())


@pytest.mark.parametrize('mode,tty_out,batch,available,expected',[
    ('auto',True,False,True,'pi'),('rich',True,False,True,'rich'),
    ('auto',True,False,False,'rich'),('pi',True,False,False,'error'),
    ('pi',False,False,True,'rich'),('auto',True,True,True,'rich')])
def test_cli_ui_selection_keeps_original_tty_and_runner_api(monkeypatch,mode,tty_out,batch,available,expected):
    from typer.testing import CliRunner
    from cli.main import app
    captured=[]
    monkeypatch.setenv('TERM','xterm-256color')
    async def rich(**kwargs):captured.append(('rich',kwargs));return 0
    async def pi(**kwargs):captured.append(('pi',kwargs));return 0
    monkeypatch.setattr('cli.session.run_session',rich)
    monkeypatch.setattr('cli.pi_session.run_pi_session',pi)
    monkeypatch.setattr('cli.pi_bridge.pi_available',lambda:(available,'fixture missing dependency'))
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
    if not available:assert 'Pi' in result.output


@pytest.mark.parametrize('kind',[{},[],None,1],ids=['object','array','null','number'])
def test_command_type_is_validated_before_mapping_lookup(kind):
    from cli.pi_bridge import PiBridge,ProtocolError
    async def scenario():
        async with PiBridge() as bridge:
            _,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            writer.write(json.dumps({'type':kind}).encode()+b'\n');await writer.drain()
            with pytest.raises(ProtocolError):await bridge.receive()
            assert bridge.disconnected.is_set()
            writer.close()
    asyncio.run(scenario())


def test_auth_pending_reply_is_backend_owned_and_exact_codes_remain_independent(tmp_path):
    from cli.pi_bridge import PiBridge
    from cli.pi_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM,response
    async def scenario():
        llm=ScriptedLLM(response('fixture',{'target':'example.com'}),response('ask_user',{'question':'Next?'}))
        runtime,tool,gate=fixture(tmp_path,llm,level=2)
        async with runtime,PiBridge() as bridge:
            reader,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            async def state():
                while True:
                    event=json.loads(await asyncio.wait_for(reader.readline(),3))
                    if event['type']=='state':return event
            await state()
            for text in ['inspect','CONFIRM 2','example.com','I UNDERSTAND AND AUTHORIZE']:
                writer.write(json.dumps({'type':'input','text':text}).encode()+b'\n');await writer.drain()
                current=await state();assert tool.calls==0
            assert gate.current_level()==2
            writer.write(b'{"type":"input","text":"yes"}\n');await writer.drain();await state()
            assert tool.calls==1
            writer.write(b'{"type":"quit"}\n');await writer.drain();await task;writer.close()
    asyncio.run(scenario())


def test_slow_ui_queue_is_bounded_and_cancels_active_graph(tmp_path):
    from cli.pi_bridge import PiBridge
    from cli.pi_session import serve_runtime
    from tests.unit.test_session_graph import fixture,ScriptedLLM
    async def scenario():
        started=asyncio.Event();cancelled=asyncio.Event()
        class Waiting(ScriptedLLM):
            async def complete(self,*args):
                started.set()
                try:await asyncio.Event().wait()
                finally:self.guard.register(2,3);cancelled.set()
        runtime,tool,gate=fixture(tmp_path,Waiting())
        async with runtime,PiBridge() as bridge:
            _,writer=await asyncio.open_connection('127.0.0.1',bridge.port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            task=asyncio.create_task(serve_runtime(runtime,gate,bridge))
            writer.write(b'{"type":"input","text":"inspect"}\n');await writer.drain();await started.wait()
            for _ in range(1000):bridge.emit({'type':'note','text':'slow '*1000})
            assert bridge.queue.qsize()<=128 and bridge.disconnected.is_set()
            await asyncio.wait_for(task,3)
            assert cancelled.is_set() and tool.calls==0 and (await runtime.state())['used_tokens']>=5
            writer.close()
    asyncio.run(scenario())


def test_installed_pi_probe_and_old_node_rejected(monkeypatch):
    from cli.pi_bridge import pi_available
    from types import SimpleNamespace
    assert pi_available()==(True,'')
    monkeypatch.setattr('cli.pi_bridge.subprocess.run',lambda *args,**kwargs:SimpleNamespace(returncode=0,stdout='20.0.0'))
    assert not pi_available()[0] and '22.19.0' in pi_available()[1]


def test_authenticated_bridge_refuses_a_second_frontend_and_releases_port():
    from cli.pi_bridge import PiBridge
    async def scenario():
        async with PiBridge() as bridge:
            port=bridge.port
            _,writer=await asyncio.open_connection('127.0.0.1',port)
            writer.write(json.dumps({'type':'hello','token':bridge.token}).encode()+b'\n');await writer.drain();await bridge.wait_connected()
            assert not bridge.server.is_serving()
            with pytest.raises(OSError):await asyncio.open_connection('127.0.0.1',port)
            writer.close()
        server=await asyncio.start_server(lambda r,w:w.close(),'127.0.0.1',port)
        server.close();await server.wait_closed()
    asyncio.run(scenario())
