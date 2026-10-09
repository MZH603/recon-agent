import asyncio
import json
import sys
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from tools.integration_config import CustomToolConfig, MCPServerConfig
from tools.custom import build_custom_tools, CustomToolParams
from tools.integration_http import guarded_http_get
from utils.config import Settings


def test_configuration_enforces_code_owned_limits():
    for config in [dict(name='x',kind='command',command=['echo'],min_level=1),
                   dict(name='x',kind='http',url='https://example.com',method='POST'),
                   dict(name='x',kind='command',command=['echo'],timeout_seconds=121),
                   dict(name='x',kind='command',command=['echo'],max_output_bytes=2097153),
                   dict(name='x',kind='command',command=['echo'],scan_level=2),
                   dict(name='x',kind='command',command=['echo {target.host}']),
                   dict(name='x',kind='command',command=['echo {missing}'])]:
        with pytest.raises(ValidationError):
            CustomToolConfig(**config)
    with pytest.raises(ValidationError):
        MCPServerConfig(name='bad',transport='stdio',command='echo',allowed_tools=['navigate'])
    assert MCPServerConfig(name='ok',transport='stdio',command='echo',allowed_tools=['snapshot'],target_fields={'snapshot':[]}).enabled is False


def tools(tmp_path, configs):
    return build_custom_tools(SimpleNamespace(custom_tools=configs,TOOL_EVIDENCE_DIR=str(tmp_path),LAB_MODE=True,REQUEST_DELAY_RANGE=(0,0),MAX_CONCURRENCY=1))


def test_command_preserves_literal_arguments_and_complete_json(tmp_path):
    config = CustomToolConfig(name='literal',kind='command',command=[sys.executable,'-c','import json,sys; print(json.dumps(sys.argv[1:]))','{target}','{value}'],
        input_schema={'type':'object','properties':{'value':{'type':'string'}},'required':['value'],'additionalProperties':False},response_format='json')
    tool = tools(tmp_path,[config])[0]
    result = asyncio.run(tool.run(CustomToolParams(target='example.com',arguments={'value':'x; $(echo exploit) & "quoted"'})))
    assert result.success, result.error
    assert result.data['output']==['example.com','x; $(echo exploit) & "quoted"']
    assert len(result.source_hash)==64
    assert result.data['evidence_id']


def test_invalid_arguments_never_spawn(tmp_path,monkeypatch):
    config = CustomToolConfig(name='required',kind='command',command=['missing','{count}'],input_schema={'type':'object','properties':{'count':{'type':'integer'}},'required':['count']})
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com',arguments={'count':'oops'})))
    assert not result.success and 'schema' in result.error.lower()


def test_output_cap_timeout_and_jsonl(tmp_path):
    cap = CustomToolConfig(name='cap',kind='command',command=[sys.executable,'-c','print("x"*1000000)'],max_output_bytes=128)
    result=asyncio.run(tools(tmp_path,[cap])[0].run(CustomToolParams(target='example.com')))
    assert result.degraded and result.data['truncated']
    assert len(result.stdout.encode())<=128
    timeout=CustomToolConfig(name='wait',kind='command',command=[sys.executable,'-c','import time; time.sleep(30)'],timeout_seconds=1)
    result=asyncio.run(tools(tmp_path,[timeout])[0].run(CustomToolParams(target='example.com')))
    assert not result.success and result.exit_code==124
    lines=CustomToolConfig(name='lines',kind='command',command=[sys.executable,'-c','import json; print(json.dumps(dict(a=1))); print(json.dumps(dict(a=2)))'],response_format='jsonl')
    result=asyncio.run(tools(tmp_path,[lines])[0].run(CustomToolParams(target='example.com')))
    assert result.data['output']==[{'a':1},{'a':2}]


def test_shell_only_hints_and_duplicate_rejected(tmp_path):
    config=CustomToolConfig(name='hint',kind='shell',command=['echo','{target}'])
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.success and result.data['executed'] is False
    assert result.data['argv']==['echo','example.com']
    with pytest.raises(ValueError,match='duplicate'):
        tools(tmp_path,[config,config])


def test_secret_redaction_and_safe_spawn_error(tmp_path,monkeypatch):
    monkeypatch.setenv('SECRET_TEST','sensitive-demo-value')
    config=CustomToolConfig(name='secret',kind='command',command=[sys.executable,'-c','import os; print(os.environ["AUTH"])'],env={'AUTH':'SECRET_TEST'})
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.success and 'sensitive-demo-value' not in result.model_dump_json()
    from tools.evidence_store import EvidenceStore
    assert 'sensitive-demo-value' not in json.dumps(EvidenceStore(tmp_path).get(result.data['evidence_id']))


def test_http_scope_resolution_redirect_and_caps():
    async def check():
        calls=[]
        async def server(reader,writer):
            line=await reader.readline(); calls.append(line)
            while await reader.readline() not in (b'\r\n',b''):
                pass
            path=line.split()[1]
            if path==b'/redirect':
                writer.write(b'HTTP/1.1 302 Found\r\nLocation: http://outside.example/\r\nContent-Length: 0\r\n\r\n')
            else:
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n'+b'x'*100)
            await writer.drain(); writer.close(); await writer.wait_closed()
        srv=await asyncio.start_server(server,'127.0.0.1',0)
        port=srv.sockets[0].getsockname()[1]; url=f'http://127.0.0.1:{port}'
        try:
            with pytest.raises(ValueError):
                await guarded_http_get(url,url,settings=Settings(LAB_MODE=False))
            assert not calls
            response=await guarded_http_get(url,url,settings=Settings(LAB_MODE=True),max_bytes=16)
            assert response['body']==b'x'*16 and response['truncated']
            with pytest.raises(ValueError,match='scope') as caught:
                await guarded_http_get(url+'/redirect',url,settings=Settings(LAB_MODE=True))
            assert caught.value.request_count==1
            assert len(calls)==2
        finally:
            srv.close(); await srv.wait_closed()
    asyncio.run(check())


def test_command_cancellation_reaps_process(tmp_path,monkeypatch):
    import tools.custom as module
    original=asyncio.create_subprocess_exec
    spawned=[]
    async def capture(*args,**kwargs):
        proc=await original(*args,**kwargs); spawned.append(proc); return proc
    monkeypatch.setattr(module.asyncio,'create_subprocess_exec',capture)
    config=CustomToolConfig(name='cancel',kind='command',command=[sys.executable,'-c','import time; time.sleep(30)'])
    async def run():
        task=asyncio.create_task(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
        while not spawned and not task.done():
            await asyncio.sleep(.01)
        assert spawned, 'subprocess could not start: '+str(task.result()) if task.done() else 'subprocess did not start'
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert spawned[0].returncode is not None
    asyncio.run(run())


def test_invalid_json_schema_is_validation_error():
    with pytest.raises(ValidationError):
        CustomToolConfig(name='bad',kind='command',command=['echo'],input_schema={'type':'object','properties':{'x':{'type':'incorrect'}}})


def test_large_json_escaped_output_retains_bounded_evidence(tmp_path):
    config=CustomToolConfig(name='big',kind='command',command=[sys.executable,'-c','import sys; sys.stdout.write(chr(1)*500000)'],max_output_bytes=2097152)
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.success, result.error
    from tools.evidence_store import EvidenceStore
    record=EvidenceStore(tmp_path).get(result.data['evidence_id'])
    assert record['payload']['stdout']==result.stdout
    assert record['size_bytes']<=2097152
    assert result.degraded


def test_script_ast_and_bounded_runtime(tmp_path,monkeypatch):
    from scripts import sandbox
    bad=CustomToolConfig(name='unsafe',kind='script',script='import os\nos.system("echo bad")')
    result=asyncio.run(tools(tmp_path,[bad])[0].run(CustomToolParams(target='example.com')))
    assert not result.success
    async def bandit_pass(code,path): return []
    monkeypatch.setattr(sandbox,'run_bandit',bandit_pass)
    good=CustomToolConfig(name='scripted',kind='script',script='print(RECON_INPUT["target"]); print(RECON_INPUT["arguments"]["value"])',
        input_schema={'type':'object','properties':{'value':{'type':'string'}},'required':['value']})
    result=asyncio.run(tools(tmp_path,[good])[0].run(CustomToolParams(target='example.com',arguments={'value':'literal; shell'})))
    assert result.success and result.stdout.splitlines()==['example.com','literal; shell'] and result.degraded


def test_http_total_deadline_chunked_and_strict_redirect_origin():
    async def check():
        clients=[]
        async def server(reader,writer):
            clients.append(writer)
            line=await reader.readline()
            while await reader.readline() not in (b'\r\n',b''): pass
            if b'/chunked ' in line:
                writer.write(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n')
                await writer.drain(); writer.close()
            elif b'/redirect ' in line:
                writer.write(b'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n'); await writer.drain(); writer.close()
            else:
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n'); await writer.drain()
                await reader.read(); writer.close()
        srv=await asyncio.start_server(server,'127.0.0.1',0)
        url=f'http://127.0.0.1:{srv.sockets[0].getsockname()[1]}'
        try:
            settings=Settings(LAB_MODE=True)
            response=await guarded_http_get(url+'/chunked',url,settings=settings,max_bytes=4)
            assert response['body']==b'abcd' and response['truncated']
            with pytest.raises(ValueError,match='scope'):
                await guarded_http_get(url+'/redirect',url,settings=settings,strict_origin=True)
            with pytest.raises(asyncio.TimeoutError) as caught:
                await guarded_http_get(url+'/slow',url,settings=settings,timeout=.2)
            assert caught.value.request_count==1
        finally:
            srv.close(); await srv.wait_closed()
            for client in clients:
                client.close()
    asyncio.run(check())

def test_script_timeout_includes_bandit_validation(tmp_path,monkeypatch):
    from scripts import sandbox
    async def slow_bandit(code,path):
        await asyncio.sleep(2)
        return ['validator delayed']
    monkeypatch.setattr(sandbox,'run_bandit',slow_bandit)
    config=CustomToolConfig(name='deadline',kind='script',script='print(target)',timeout_seconds=1)
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.exit_code==124


def test_arguments_cannot_shadow_declared_target(tmp_path):
    config=CustomToolConfig(name='hint',kind='shell',command=['echo','{target}'],input_schema={'type':'object','additionalProperties':True})
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com',arguments={'target':'outside.com'})))
    assert not result.success

@pytest.mark.parametrize('field',['code','command','script','min_level','scan_level','LAB_MODE','GATE_PER_STEP_CONFIRM','url'])
def test_protected_extra_arguments_never_dispatch(tmp_path,monkeypatch,field):
    import tools.custom as module
    dispatched=[]
    async def fake(*args,**kwargs):
        dispatched.append(args)
        return 0,'','',False
    monkeypatch.setattr(module,'_bounded_process',fake)
    config=CustomToolConfig(name='protected',kind='command',command=['echo','{target}'],input_schema={'type':'object','additionalProperties':True})
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com',arguments={field:'override'})))
    assert not result.success and not dispatched


@pytest.mark.parametrize('reference',['$ref','$dynamicRef'])
def test_external_schema_references_rejected_recursively(reference):
    schema={'type':'object','properties':{'nested':{'type':'array','items':{reference:'https://outside.example/schema'}}}}
    with pytest.raises(ValidationError):
        CustomToolConfig(name='ref',kind='command',command=['echo'],input_schema=schema)

def test_docker_missing_records_actual_host_isolation(tmp_path,monkeypatch):
    import tools.custom as module
    async def bandit_pass(code,path): return []
    async def process(*args,**kwargs): return 0,'safe','',False
    monkeypatch.setattr(module.sandbox,'run_bandit',bandit_pass)
    monkeypatch.setattr(module,'find_tool',lambda name:None)
    monkeypatch.setattr(module,'_bounded_process',process)
    config=CustomToolConfig(name='host',kind='script',script='print(target)')
    tool=tools(tmp_path,[config])[0]; tool.settings.SANDBOX_USE_DOCKER=True
    result=asyncio.run(tool.run(CustomToolParams(target='example.com')))
    assert result.success and result.degraded
    assert result.data['isolation']=='host'


def test_dynamic_adapter_and_search_are_never_cached(tmp_path):
    from tools.evidence_tools import build_evidence_tools
    config=CustomToolConfig(name='state',kind='shell',command=['echo','{target}'])
    assert tools(tmp_path,[config])[0].cacheable is False
    search=next(t for t in build_evidence_tools(SimpleNamespace(TOOL_EVIDENCE_DIR=str(tmp_path))) if t.name=='evidence_search')
    assert search.cacheable is False

@pytest.mark.parametrize('format',['json','jsonl'])
@pytest.mark.parametrize('kind',['command','http'])
def test_unicode_escaped_credentials_redacted_after_json_decoding(tmp_path,monkeypatch,format,kind):
    import tools.custom as module
    monkeypatch.setenv('UNICODE_SOURCE','credential-secret')
    escaped=''.join('\\u%04x'%ord(char) for char in 'credential-secret')
    raw='"'+escaped+'"'
    async def process(*args,**kwargs): return 0,raw,'',False
    monkeypatch.setattr(module,'_bounded_process',process)
    async def http(*args,**kwargs):
        return {'status':200,'url':'https://example.com','body':raw.encode(),'headers':{},'truncated':False,'request_count':1}
    monkeypatch.setattr(module,'guarded_http_get',http)
    config=CustomToolConfig(name='encoded',kind=kind,command=['unused'],url='https://example.com',response_format=format,env={'TOKEN':'UNICODE_SOURCE'})
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.success and 'credential-secret' not in result.model_dump_json()
    assert result.data['output']==('[REDACTED]' if format=='json' else ['[REDACTED]'])
    from tools.evidence_store import EvidenceStore
    saved=EvidenceStore(tmp_path).get(result.data['evidence_id'])
    assert json.loads(saved['payload']['stdout'])=='[REDACTED]'


def test_evidence_failed_write_does_not_publish_partial_id(tmp_path,monkeypatch):
    from pathlib import Path
    from tools.evidence_store import EvidenceStore
    original=Path.open
    class Interrupted:
        def __init__(self,handle): self.handle=handle
        def __enter__(self): self.handle.__enter__(); return self
        def __exit__(self,*args): return self.handle.__exit__(*args)
        def write(self,data):
            self.handle.write(data[:10]); self.handle.flush()
            raise OSError('simulated interruption')
    def fail_write(path,mode='r',*args,**kwargs):
        handle=original(path,mode,*args,**kwargs)
        return Interrupted(handle) if 'b' in mode and any(c in mode for c in ('w','x')) else handle
    monkeypatch.setattr(Path,'open',fail_write)
    store=EvidenceStore(tmp_path)
    with pytest.raises(OSError): store.put('example.com','fixture',{'complete':True})
    assert not list(tmp_path.glob('*.json'))
    monkeypatch.setattr(Path,'open',original)
    evidence_id=store.put('example.com','fixture',{'complete':True})
    assert store.get(evidence_id)['payload']=={'complete':True}


def test_http_sensitive_response_headers_never_public(tmp_path,monkeypatch):
    import tools.custom as module
    async def http(*args,**kwargs):
        return {'status':200,'url':'https://example.com','body':b'ok','headers':{'set-cookie':'session=raw-cookie','authorization':'raw-auth','proxy-authorization':'raw-proxy','cookie':'raw-cookie','x-safe':'ok'},'truncated':False,'request_count':1}
    monkeypatch.setattr(module,'guarded_http_get',http)
    config=CustomToolConfig(name='headers',kind='http',url='https://example.com')
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.success and 'raw-cookie' not in result.model_dump_json() and 'raw-auth' not in result.model_dump_json() and 'raw-proxy' not in result.model_dump_json()
    assert result.data['headers']['x-safe']=='ok'

def test_custom_http_acquires_existing_rate_limiter(tmp_path,monkeypatch):
    from contextlib import asynccontextmanager
    import tools.custom as module
    events=[]
    class Limiter:
        def __init__(self,*args): pass
        @asynccontextmanager
        async def slot(self):
            events.append('slot')
            try: yield
            finally: events.append('release')
    async def http(*args,**kwargs):
        events.append('fetch')
        return {'status':200,'url':'https://example.com','body':b'ok','headers':{},'truncated':False,'request_count':1}
    monkeypatch.setattr(module,'StealthRateLimiter',Limiter,raising=False)
    monkeypatch.setattr(module,'guarded_http_get',http)
    config=CustomToolConfig(name='limited',kind='http',url='https://example.com')
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.success and events==['slot','fetch','release']


def test_custom_http_deadline_includes_rate_limit_delay(tmp_path,monkeypatch):
    from contextlib import asynccontextmanager
    import tools.custom as module
    dispatched=[]
    class Limiter:
        def __init__(self,*args): pass
        @asynccontextmanager
        async def slot(self):
            await asyncio.sleep(2)
            yield
    async def http(*args,**kwargs):
        dispatched.append(True)
        return {'status':200,'url':'https://example.com','body':b'ok','headers':{},'truncated':False,'request_count':1}
    monkeypatch.setattr(module,'StealthRateLimiter',Limiter,raising=False)
    monkeypatch.setattr(module,'guarded_http_get',http)
    config=CustomToolConfig(name='delayed',kind='http',url='https://example.com',timeout_seconds=1)
    result=asyncio.run(tools(tmp_path,[config])[0].run(CustomToolParams(target='example.com')))
    assert result.exit_code==124 and not dispatched
