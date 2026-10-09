import asyncio
from types import SimpleNamespace

import pytest

from tools.mcp_tools import MCPCallParams, MCPToolsParams, build_mcp_tools
from tools.integration_config import MCPServerConfig
from tools.evidence_store import EvidenceStore
from utils.config import Settings


def settings(tmp_path, **server_kw):
    config=dict(name='browser',enabled=True,transport='stdio',command='unused',allowed_tools=['navigate','snapshot'],target_fields={'navigate':['url'],'snapshot':[]})
    config.update(server_kw)
    return SimpleNamespace(mcp_servers=[MCPServerConfig(**config)],TOOL_EVIDENCE_DIR=tmp_path,PROTECTED_TLDS=['.gov','.mil'],LAB_MODE=False)


class FakeClient:
    def __init__(self): self.calls=[]; self.closed=0
    async def list_tools(self):
        return [{'name':'navigate','inputSchema':{'type':'object','properties':{'url':{'type':'string'}},'required':['url'],'additionalProperties':False}}, {'name':'snapshot','inputSchema':{'type':'object'}}, {'name':'denied','inputSchema':{'type':'object'}}]
    async def call_tool(self,name,args):
        self.calls.append((name,args))
        return {'content':[{'type':'text','text':'complete response'}], 'structuredContent':{'requests':[{'method':'GET','url':'https://example.com/api'}]}}
    async def aclose(self): self.closed+=1


def adapters(tmp_path, **kw):
    ts=build_mcp_tools(settings(tmp_path,**kw),'example.com')
    fake=FakeClient(); ts[0].manager.clients['browser']=fake
    return ts,fake


def test_discovery_advertises_schema_permissions_and_shared_close(tmp_path):
    async def case():
        (discovery,call),fake=adapters(tmp_path)
        assert discovery.min_level==0 and call.min_level==2
        result=await discovery.run(MCPToolsParams(target='example.com',server='browser'))
        assert result.success
        assert result.data['tools'][0]['inputSchema']['required']==['url']
        assert result.data['tools'][2]['allowed'] is False
        await discovery.aclose(); await call.aclose()
        assert fake.closed==1
    asyncio.run(case())


@pytest.mark.parametrize('tool,args,target', [('denied',{},'example.com'),('missing',{},'example.com'),('navigate',{},'example.com'),('navigate',{'url':'https://elsewhere.com'},'example.com'),('navigate',{'url':'https://x.gov'},'example.com'),('navigate',{'url':'https://example.com'},'elsewhere.com'),('navigate',{'url':'file:///etc/passwd'},'example.com')])
def test_denied_invalid_outside_scope_never_dispatch(tmp_path,tool,args,target):
    async def case():
        ts,fake=adapters(tmp_path)
        result=await ts[1].run(MCPCallParams(target=target,server='browser',tool=tool,arguments=args))
        assert not result.success and not fake.calls
    asyncio.run(case())


def test_missing_target_policy_denies_even_allowed_tool(tmp_path):
    async def case():
        ts,fake=adapters(tmp_path)
        # Runtime still fails closed if a previously validated policy is mutated.
        ts[1].manager.configs['browser'].target_fields={'navigate':['url']}
        r=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot',arguments={}))
        assert not r.success and not fake.calls
    asyncio.run(case())


def test_snapshot_and_navigation_store_complete_evidence(tmp_path):
    async def case():
        ts,fake=adapters(tmp_path)
        r=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot',arguments={}))
        assert r.success and len(r.source_hash)==64
        saved=EvidenceStore(tmp_path).get(r.data['evidence_id'])
        assert saved['payload']['result']['content'][0]['text']=='complete response'
        assert saved['payload']['result']['structuredContent']['requests'][0]['method']=='GET'
        assert r.evidence
    asyncio.run(case())


def test_disabled_no_build_and_min_level_config(tmp_path):
    assert build_mcp_tools(settings(tmp_path,enabled=False),'example.com')==[]
    assert MCPCallParams.model_json_schema()['required']==['target','server','tool']


def test_remote_iserror_and_secret_redaction_keeps_bounded_complete_evidence(tmp_path,monkeypatch):
    monkeypatch.setenv('MCP_SECRET','sensitive-test-token')
    async def case():
        ts,fake=adapters(tmp_path,env={'TOKEN':'MCP_SECRET'})
        async def error_call(name,args):
            return {'isError':True,'content':[{'type':'text','text':'sensitive-test-token'}]}
        fake.call_tool=error_call
        r=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot'))
        assert not r.success and r.data['evidence_id']
        assert 'sensitive-test-token' not in r.model_dump_json()
        saved=EvidenceStore(tmp_path).get(r.data['evidence_id'])
        assert saved['payload']['result']['content'][0]['text']=='[REDACTED]'
    asyncio.run(case())


def test_duplicate_servers_rejected_before_connect(tmp_path):
    s=settings(tmp_path);s.mcp_servers*=2
    with pytest.raises(ValueError,match='Duplicate'):
        build_mcp_tools(s,'example.com')


def test_subtarget_cannot_navigate_parent_and_schema_external_ref_denied(tmp_path):
    async def case():
        ts,fake=adapters(tmp_path)
        r=await ts[1].run(MCPCallParams(target='sub.example.com',server='browser',tool='navigate',arguments={'url':'https://example.com'}))
        assert not r.success and not fake.calls
        async def schema_list(): return [{'name':'snapshot','inputSchema':{'$ref':'https://outside.test/schema'}}]
        fake.list_tools=schema_list
        r=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot'))
        assert not r.success and not fake.calls
    asyncio.run(case())


def test_oversized_adapter_response_not_published(tmp_path):
    async def case():
        ts,fake=adapters(tmp_path,max_output_bytes=128)
        async def call(name,args): return {'content':[{'type':'text','text':'x'*1000}]}
        fake.call_tool=call
        r=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot'))
        assert not r.success and not r.data and not list(tmp_path.glob('*.json'))
    asyncio.run(case())


def test_stateful_connector_cannot_rebind_snapshot_evidence(tmp_path):
    async def case():
        ts,fake=adapters(tmp_path)
        first=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot'))
        assert first.success
        second=await ts[1].run(MCPCallParams(target='sub.example.com',server='browser',tool='snapshot'))
        assert not second.success and len(fake.calls)==1
        discovery=await ts[0].run(MCPToolsParams(target='sub.example.com',server='browser'))
        assert not discovery.success
    asyncio.run(case())


def test_jsonrpc_error_evidence_redacts_remote_diagnostics(tmp_path,monkeypatch):
    from tools.mcp_client import MCPError
    monkeypatch.setenv('MCP_SECRET','error-credential')
    async def case():
        ts,fake=adapters(tmp_path,env={'TOKEN':'MCP_SECRET'})
        async def error_call(name,args):
            raise MCPError('Remote MCP JSON-RPC error',response={'jsonrpc':'2.0','id':1,'error':{'code':-32603,'message':'error-credential'}})
        fake.call_tool=error_call
        r=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot'))
        assert not r.success and r.data['evidence_id'] and len(r.source_hash)==64
        saved=EvidenceStore(tmp_path).get(r.data['evidence_id'])
        assert saved['payload']['result']['error']['message']=='[REDACTED]'
        assert 'error-credential' not in r.model_dump_json()
    asyncio.run(case())


def test_large_complete_result_not_duplicated_in_evidence(tmp_path):
    async def case():
        ts,fake=adapters(tmp_path,max_output_bytes=2097152)
        remote={'structuredContent':{'requests':[{'method':'GET','url':'https://example.com/api?data='+'x'*1100000}]},'content':[]}
        async def large_call(name,args):return remote
        fake.call_tool=large_call
        result=await ts[1].run(MCPCallParams(target='example.com',server='browser',tool='snapshot'))
        assert result.success,result.error
        saved=EvidenceStore(tmp_path).get(result.data['evidence_id'])
        assert saved['payload']['result']==remote
    asyncio.run(case())
