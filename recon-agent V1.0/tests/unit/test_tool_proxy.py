import asyncio
from types import SimpleNamespace
import pytest
from pydantic import ValidationError


def module():
    from tools.adapters import proxy
    return proxy


def settings(tmp_path,**config):
    return SimpleNamespace(extension_tools=SimpleNamespace(caido=config),TOOL_EVIDENCE_DIR=str(tmp_path),LAB_MODE=False,PROTECTED_TLDS=('.gov','.mil'))


def test_default_and_schema(tmp_path):
    m=module()
    assert not m.CaidoConfig().enabled
    assert m.build_proxy_tools(settings(tmp_path))==[]
    for bad in ({'url':'file:///x'},{'url':'http://user:pass@localhost'},{'bearer':'secret'},{'timeout_seconds':121}):
        with pytest.raises(ValidationError):m.CaidoConfig(**bad)
    with pytest.raises(ValidationError):m.ProxyListParams(target='example.com',query='mutation')


def fake_transport(monkeypatch):
    state={'active':0,'max_active':0,'calls':[]}
    def req(host,identifier='1'):
        return dict(id=identifier,host=host,port=443,method='GET',path='/api',is_tls=True)
    own={**req('example.com'),'response':{'status_code':200}}
    foreign={**req('foreign.test','foreign'),'response':None}
    candidate={**req('api.example.com','candidate'),'response':None}
    async def post(origin,path,payload,headers,timeout,max_bytes):
        state['calls'].append(payload)
        assert origin=='http://127.0.0.1:48080' and path=='/graphql'
        assert 'raw' not in payload['query'] and 'mutation' not in payload['query']
        state['active']+=1;state['max_active']=max(state['max_active'],state['active'])
        await asyncio.sleep(0.01);state['active']-=1
        if 'id' in payload['variables']:return {'data':{'request':foreign if payload['variables']['id']=='foreign' else own}},False
        assert payload['variables']['first']<=50
        return {'data':{'requests':{'edges':[{'node':x} for x in (own,foreign,candidate)],'page_info':{'has_next_page':False,'end_cursor':None}}}},False
    monkeypatch.setattr(module(),'bounded_json_post',post)
    monkeypatch.setenv('CAIDO_TOKEN','secret-value')
    return state


def test_request_scope_redaction_and_transport_lifecycle(tmp_path,monkeypatch):
    m=module();state=fake_transport(monkeypatch)
    tools=m.build_proxy_tools(settings(tmp_path,enabled=True))
    assert [t.name for t in tools]==['list_requests','view_request','list_sitemap']
    async def scenario():
        results=await asyncio.gather(tools[0].run(m.ProxyListParams(target='example.com')),tools[2].run(m.ProxyListParams(target='example.com')))
        for result in results:
            assert result.success and result.evidence and result.source_hash
            assert len(result.data['result']['requests'])==2
            assert result.data['result']['requests'][1]['candidate']
            assert 'secret-value' not in result.model_dump_json() and 'foreign.test' not in result.model_dump_json()
        rejected=await tools[1].run(m.ProxyViewParams(target='example.com',request_id='foreign'))
        assert not rejected.success and 'scope' in rejected.error
        viewed=await tools[1].run(m.ProxyViewParams(target='example.com',request_id='1'))
        assert viewed.success and 'body-secret' not in viewed.model_dump_json()
        for tool in tools:await tool.aclose()
    asyncio.run(scenario())
    assert state['max_active']==1 and all(tool.manager.closed for tool in tools)


def test_missing_credential_no_client_creation(tmp_path,monkeypatch):
    m=module();monkeypatch.delenv('CAIDO_TOKEN',raising=False)
    tool=m.build_proxy_tools(settings(tmp_path,enabled=True))[0]
    result=asyncio.run(tool.run(m.ProxyListParams(target='example.com')))
    assert not result.success and 'credential' in result.error


def test_oversized_service_response_fails_explicitly(tmp_path,monkeypatch):
    m=module();monkeypatch.setenv('CAIDO_TOKEN','secret')
    async def huge(*args,**kwargs):return {},True
    monkeypatch.setattr(m,'bounded_json_post',huge)
    tool=m.build_proxy_tools(settings(tmp_path,enabled=True,max_output_bytes=128))[1]
    result=asyncio.run(tool.run(m.ProxyViewParams(target='example.com',request_id='1')))
    assert not result.success and 'byte limit' in result.error


def test_metadata_query_parameter_names_only(tmp_path,monkeypatch):
    m=module();monkeypatch.setenv('CAIDO_TOKEN','bearer-key')
    async def metadata(*args,**kwargs):
        return {'data':{'request':{'id':'1','host':'example.com','port':443,'is_tls':True,'method':'GET','path':'/api?token=secret&page=1','query':'token=secret&page=1','response':{'status_code':200}}}},False
    monkeypatch.setattr(m,'bounded_json_post',metadata)
    tool=m.build_proxy_tools(settings(tmp_path,enabled=True))[1]
    result=asyncio.run(tool.run(m.ProxyViewParams(target='example.com',request_id='1')))
    assert result.success
    assert result.data['result']['requests'][0]['params']==['page','token']
    assert 'secret' not in result.model_dump_json()


def test_service_timeout_marks_remote_outcome_unknown(tmp_path,monkeypatch):
    m=module();monkeypatch.setenv('CAIDO_TOKEN','key')
    async def timeout(*args,**kwargs):raise asyncio.TimeoutError
    monkeypatch.setattr(m,'bounded_json_post',timeout)
    tool=m.build_proxy_tools(settings(tmp_path,enabled=True))[0]
    result=asyncio.run(tool.run(m.ProxyListParams(target='example.com')))
    assert tool.remote_execution and result.status=='timeout' and result.outcome_unknown
