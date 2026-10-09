import asyncio
import json
from types import SimpleNamespace
import pytest
from pydantic import ValidationError


def module():
    from tools.adapters import search
    return search


def settings(tmp_path, **config):
    return SimpleNamespace(extension_tools=SimpleNamespace(search=config),TOOL_EVIDENCE_DIR=str(tmp_path),PROTECTED_TLDS=('.gov','.mil'),LAB_MODE=False)


def test_optional_registration_and_closed_config(tmp_path):
    m=module()
    assert not m.SearchConfig().enabled
    assert m.build_search_tools(settings(tmp_path))==[]
    for bad in ({'provider':'other'},{'api_key':'secret'},{'url':'https://evil'},{'max_output_bytes':300000}):
        with pytest.raises(ValidationError):m.SearchConfig(**bad)
    assert [t.name for t in m.build_search_tools(settings(tmp_path,enabled=True,provider='perplexity'))]==['web_search']
    with pytest.raises(ValidationError):m.SearchParams(target='example.com',query='q',url='https://evil')


@pytest.mark.parametrize('provider',['exa','perplexity'])
def test_parsed_unverified_results_redact_keys(tmp_path,monkeypatch,provider):
    m=module();secret='key-demo-value';monkeypatch.setenv('TEST_SEARCH_KEY',secret);calls=[]
    async def fake(service,path,payload,headers,timeout,max_bytes):
        calls.append((service,path,payload))
        if provider=='exa':return {'results':[{'url':'https://source.example/a','title':'Title','text':secret,'summary':'A summary'}]},False
        return {'choices':[{'message':{'content':secret+' answer'}}],'citations':['https://source.example/a']},False
    monkeypatch.setattr(m,'_service_post',fake)
    tool=m.build_search_tools(settings(tmp_path,enabled=True,provider=provider,api_key_env='TEST_SEARCH_KEY'))[0]
    result=asyncio.run(tool.run(m.SearchParams(target='example.com',query='public information')))
    assert result.success and result.source_hash and result.evidence
    assert secret not in result.model_dump_json()
    assert result.data['result']['unverified']
    if provider=='exa':assert result.data['result']['sources'][0]['summary']=='A summary'
    else:assert result.data['result']['citations']==['https://source.example/a']
    assert tool.deferred and not tool.cacheable


def test_missing_key_and_service_error_do_not_echo_secret(tmp_path,monkeypatch):
    m=module();monkeypatch.delenv('TEST_SEARCH_KEY',raising=False)
    tool=m.build_search_tools(settings(tmp_path,enabled=True,api_key_env='TEST_SEARCH_KEY'))[0]
    result=asyncio.run(tool.run(m.SearchParams(target='example.com',query='q')))
    assert not result.success and 'credential' in result.error
    monkeypatch.setenv('TEST_SEARCH_KEY','dont-echo')
    async def failure(*args,**kwargs):raise RuntimeError('dont-echo')
    monkeypatch.setattr(m,'_service_post',failure)
    result=asyncio.run(tool.run(m.SearchParams(target='example.com',query='q')))
    assert not result.success and 'dont-echo' not in result.model_dump_json()


def test_contents_limits_and_cancel(tmp_path,monkeypatch):
    m=module();monkeypatch.setenv('EXA_API_KEY','test')
    tools=m.build_search_tools(settings(tmp_path,enabled=True))
    assert [t.name for t in tools]==['web_search','web_get_contents']
    with pytest.raises(ValidationError):m.ContentsParams(target='example.com',urls=['file:///tmp/x'])
    async def cancelled(*args,**kwargs):raise asyncio.CancelledError
    monkeypatch.setattr(m,'_service_post',cancelled)
    with pytest.raises(asyncio.CancelledError):asyncio.run(tools[1].run(m.ContentsParams(target='example.com',urls=['https://public.example/x'])))


@pytest.mark.parametrize('status,body,max_bytes,expected',[(302,b'{}',128,'redirect'),(200,b'{"results":[]}',128,'ok'),(200,b'x'*300,128,'truncated')])
def test_service_socket_bounded_and_closed(monkeypatch,status,body,max_bytes,expected):
    m=module();state={'closed':False,'sent':b'','connections':0}
    class Writer:
        def write(self,data):state['sent']+=data
        async def drain(self):pass
        def close(self):state['closed']=True
        async def wait_closed(self):pass
    async def connect(host,port,**kwargs):
        state['connections']+=1
        assert host=='api.exa.ai' and port==443
        reader=asyncio.StreamReader()
        reader.feed_data(f'HTTP/1.1 {status} Response\r\nContent-Length: {len(body)}\r\nLocation: https://evil/\r\n\r\n'.encode()+body);reader.feed_eof()
        return reader,Writer()
    monkeypatch.setattr(m.asyncio,'open_connection',connect)
    if expected=='redirect':
        with pytest.raises(ValueError):asyncio.run(m._service_post('exa','/search',{'query':'q'},{'x-api-key':'test'},2,max_bytes))
    else:
        data,truncated=asyncio.run(m._service_post('exa','/search',{'query':'q'},{'x-api-key':'test'},2,max_bytes))
        assert truncated==(expected=='truncated')
    assert state['closed'] and state['connections']==1


def test_redacts_percent_and_unicode_escaped_secret():
    m=module()
    assert 'clé-test' not in m.redact({'answer':'cl%C3%A9-test and cl\\u00e9-test'},'clé-test')['answer']
    assert 'cl\\u00e9-test' not in m.redact('cl\\u00e9-test','clé-test')


def test_redaction_preserves_unrelated_percent_encoded_url():
    m=module()
    assert m.redact('https://source.example/a%2Fb?q=x%20y','key-demo')=='https://source.example/a%2Fb?q=x%20y'


def test_redacts_fully_encoded_credential_variants():
    m=module();secret='test-key'
    unicode_encoded=''.join('\\u%04x'%ord(c) for c in secret)
    percent_encoded=''.join('%%%02x'%b for b in secret.encode())
    assert unicode_encoded not in m.redact('Answer '+unicode_encoded,secret)
    assert percent_encoded not in m.redact('URL '+percent_encoded,secret)


def test_cancel_during_body_read_closes_real_transport(monkeypatch):
    m=module();state={'closed':False}
    class Writer:
        def write(self,data):pass
        async def drain(self):pass
        def close(self):state['closed']=True
        async def wait_closed(self):pass
    async def connect(*args,**kwargs):
        reader=asyncio.StreamReader();reader.feed_data(b'HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n')
        return reader,Writer()
    monkeypatch.setattr(m.asyncio,'open_connection',connect)
    async def scenario():
        task=asyncio.create_task(m._service_post('exa','/search',{'query':'q'},{'x-api-key':'test'},10,128))
        await asyncio.sleep(0.01);task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(scenario())
    assert state['closed']


def test_service_timeout_marks_remote_outcome_unknown(tmp_path,monkeypatch):
    m=module();monkeypatch.setenv('EXA_API_KEY','key')
    async def timeout(*args,**kwargs):raise asyncio.TimeoutError
    monkeypatch.setattr(m,'_service_post',timeout)
    tool=m.build_search_tools(settings(tmp_path,enabled=True))[0]
    result=asyncio.run(tool.run(m.SearchParams(target='example.com',query='q')))
    assert tool.remote_execution and result.status=='timeout' and result.outcome_unknown
