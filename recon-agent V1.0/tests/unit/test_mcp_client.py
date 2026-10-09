"""Local fake connectors exercise protocol and lifecycle without internet access."""
import asyncio
import json
import sys
from types import SimpleNamespace

import pytest

from tools.mcp_client import MCPClient, MCPError


def config(**kw):
    defaults = dict(name='fixture', transport='stdio', command=sys.executable, args=[],
                    env={}, headers_env={}, timeout_seconds=30, max_output_bytes=4096)
    defaults.update(kw)
    return SimpleNamespace(**defaults)


@pytest.fixture
def stdio_script(tmp_path):
    p = tmp_path / 'mcp_fixture.py'
    p.write_text('''import json,sys,time
for line in sys.stdin:
 q=json.loads(line); m=q['method']; i=q.get('id')
 if i is None: continue
 if m=='initialize': r={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'fake','version':'1'}}
 elif m=='tools/list':
  if q.get('params',{}).get('cursor'): r={'tools':[{'name':'snapshot','inputSchema':{'type':'object'}}]}
  else: r={'tools':[{'name':'navigate','inputSchema':{'type':'object','properties':{'url':{'type':'string'}},'required':['url'],'additionalProperties':False}}],'nextCursor':'p2'}
 elif q['params']['name']=='slow': time.sleep(10); r={}
 elif q['params']['name']=='large': r={'content':[{'type':'text','text':'x'*10000}]}
 else: r={'content':[{'type':'text','text':json.dumps({'requests':[{'method':'GET','url':q['params']['arguments'].get('url','https://example.com/api')} ]})}],'isError':q['params']['name']=='error'}
 print(json.dumps({'jsonrpc':'2.0','id':i,'result':r}),flush=True)
''', encoding='utf-8')
    return p


def test_stdio_lazy_persistent_paginated_and_close(stdio_script):
    async def case():
        c = MCPClient(config(args=[str(stdio_script)]))
        assert c.process is None
        tools = await c.list_tools()
        pid = c.process.pid
        assert [x['name'] for x in tools] == ['navigate', 'snapshot']
        result = await c.call_tool('navigate', {'url':'https://example.com'})
        assert result['content'] and c.process.pid == pid
        assert (await c.call_tool('error', {}))['isError'] is True
        await c.aclose()
        assert c.process.returncode is not None
        await c.aclose()
        with pytest.raises(MCPError): await c.list_tools()
    asyncio.run(case())


@pytest.mark.parametrize('name,timeout', [('large', 2), ('slow', .05)])
def test_stdio_bound_and_timeout_reap(stdio_script, name, timeout):
    async def case():
        c=MCPClient(config(args=[str(stdio_script)]))
        await c.list_tools()
        c.config.timeout_seconds=timeout
        with pytest.raises(MCPError): await c.call_tool(name,{})
        assert c.process.returncode is not None
        await c.aclose()
    asyncio.run(case())


def test_cancel_reaps_stdio(stdio_script):
    async def case():
        c=MCPClient(config(args=[str(stdio_script)]))
        await c.list_tools()
        t=asyncio.create_task(c.call_tool('slow',{}))
        await asyncio.sleep(.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError): await t
        assert c.process.returncode is not None
        await c.aclose()
    asyncio.run(case())


@pytest.mark.parametrize('stream', [False, True])
def test_http_session_notification_and_no_call_retry(stream):
    async def case():
        seen=[]
        async def handler(reader,writer):
            head=(await reader.readuntil(b'\r\n\r\n')).decode()
            lines=head.split('\r\n'); headers=dict(x.split(': ',1) for x in lines[1:] if ': ' in x)
            body=await reader.readexactly(int(headers.get('Content-Length','0')))
            if lines[0].startswith('DELETE'):
                writer.write(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n')
            else:
                q=json.loads(body); seen.append((q,headers))
                m=q['method']
                if m=='notifications/initialized':
                    writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n')
                elif m=='tools/call':
                    writer.write(b'HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n')
                else:
                    result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'fake','version':'1'}} if m=='initialize' else {'tools':[]}
                    b=json.dumps({'jsonrpc':'2.0','id':q['id'],'result':result}).encode()
                    if stream: b=b'event: message\ndata: '+b+b'\n\n'
                    content='text/event-stream' if stream else 'application/json'
                    writer.write(f'HTTP/1.1 200 OK\r\nContent-Type: {content}\r\nMcp-Session-Id: fixture-session\r\nContent-Length: {len(b)}\r\n\r\n'.encode()+b)
            await writer.drain(); writer.close(); await writer.wait_closed()
        srv=await asyncio.start_server(handler,'127.0.0.1',0)
        try:
            port=srv.sockets[0].getsockname()[1]
            c=MCPClient(config(transport='http',url=f'http://127.0.0.1:{port}/mcp'))
            assert await c.list_tools()==[]
            assert seen[1][0]['method']=='notifications/initialized'
            assert seen[1][1]['Mcp-Session-Id']=='fixture-session'
            assert seen[2][1]['MCP-Protocol-Version']=='2025-06-18'
            assert 'text/event-stream' in seen[0][1]['Accept']
            with pytest.raises(MCPError): await c.call_tool('effect',{})
            assert sum(x[0]['method']=='tools/call' for x in seen)==1
            await c.aclose()
        finally: srv.close(); await srv.wait_closed()
    asyncio.run(case())


def test_legacy_sse_endpoint_and_jsonrpc():
    async def case():
        stream_writer=None; seen=[]
        async def handler(reader,writer):
            nonlocal stream_writer
            head=(await reader.readuntil(b'\r\n\r\n')).decode()
            if head.startswith('GET'):
                stream_writer=writer
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nevent: endpoint\ndata: /messages\n\n')
                await writer.drain()
                await reader.read()
            else:
                length=int(next(x.split(':',1)[1] for x in head.split('\r\n') if x.lower().startswith('content-length:')))
                q=json.loads(await reader.readexactly(length)); seen.append(q)
                writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n'); await writer.drain()
                if 'id' in q:
                    r={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'fake','version':'1'}} if q['method']=='initialize' else {'tools':[]}
                    stream_writer.write(b'event: message\ndata: '+json.dumps({'jsonrpc':'2.0','id':q['id'],'result':r}).encode()+b'\n\n'); await stream_writer.drain()
            writer.close(); await writer.wait_closed()
        srv=await asyncio.start_server(handler,'127.0.0.1',0)
        try:
            c=MCPClient(config(transport='sse',url=f'http://127.0.0.1:{srv.sockets[0].getsockname()[1]}/sse'))
            assert await c.list_tools()==[]
            assert [x['method'] for x in seen]==['initialize','notifications/initialized','tools/list']
            await c.aclose()
        finally: srv.close(); await srv.wait_closed()
    asyncio.run(case())


def test_invalid_protocol_and_repeated_cursor_fail_closed(tmp_path):
    async def case(mode):
        p=tmp_path/(mode+'.py')
        p.write_text("import sys,json\nfor line in sys.stdin:\n q=json.loads(line)\n if 'id' not in q: continue\n r={'protocolVersion':"+repr('future' if mode=='protocol' else '2025-06-18')+",'capabilities':{}} if q['method']=='initialize' else {'tools':[],'nextCursor':'same'}\n print(json.dumps({'jsonrpc':'2.0','id':q['id'],'result':r}),flush=True)\n",encoding='utf-8')
        c=MCPClient(config(args=[str(p)]))
        with pytest.raises(MCPError): await c.list_tools()
        assert c.process.returncode is not None
    for mode in ['protocol','cursor']: asyncio.run(case(mode))


def test_http_chunked_multiline_sse_response():
    async def case():
        async def handler(reader,writer):
            head=(await reader.readuntil(b'\r\n\r\n')).decode()
            if head.startswith('DELETE'): writer.write(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n')
            else:
                n=int(next(l.split(':',1)[1] for l in head.split('\r\n') if l.lower().startswith('content-length:')))
                q=json.loads(await reader.readexactly(n))
                if 'id' not in q: writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n')
                else:
                    r={'protocolVersion':'2025-06-18','capabilities':{}} if q['method']=='initialize' else {'tools':[]}
                    response=json.dumps({'jsonrpc':'2.0','id':q['id'],'result':r})
                    first,second=response.split(', ',1)
                    b=(': keepalive\r\nevent: message\r\ndata: '+first+',\r\ndata: '+second+'\r\n\r\n').encode()
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n')
                    for piece in [b[:20],b[20:]]: writer.write(f'{len(piece):x}\r\n'.encode()+piece+b'\r\n')
                    writer.write(b'0\r\n\r\n')
            await writer.drain();writer.close();await writer.wait_closed()
        srv=await asyncio.start_server(handler,'127.0.0.1',0)
        try:
            c=MCPClient(config(transport='http',url=f'http://127.0.0.1:{srv.sockets[0].getsockname()[1]}/mcp'))
            assert await c.list_tools()==[]
            await c.aclose()
        finally: srv.close();await srv.wait_closed()
    asyncio.run(case())


def test_http_oversized_and_timeout_connections_close():
    async def case(large):
        disconnected=asyncio.Event()
        async def handler(reader,writer):
            await reader.readuntil(b'\r\n\r\n')
            if large:
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99999\r\n\r\n')
                await writer.drain()
            await reader.read()
            disconnected.set();writer.close();await writer.wait_closed()
        srv=await asyncio.start_server(handler,'127.0.0.1',0)
        try:
            c=MCPClient(config(transport='http',url=f'http://127.0.0.1:{srv.sockets[0].getsockname()[1]}/mcp',timeout_seconds=.1))
            with pytest.raises(MCPError): await c.list_tools()
            assert not c._writers
            await asyncio.wait_for(disconnected.wait(),1)
            await c.aclose()
        finally:srv.close();await srv.wait_closed()
    asyncio.run(case(True));asyncio.run(case(False))


def test_jsonrpc_error_retains_bounded_response_for_local_evidence():
    async def case():
        c=MCPClient(config())
        future=asyncio.get_running_loop().create_future();c._pending[1]=future
        response={'jsonrpc':'2.0','id':1,'error':{'code':-32603,'message':'remote diagnostic'}}
        c._deliver(response)
        with pytest.raises(MCPError) as error: await future
        assert error.value.response==response
        c._pending.clear();await c.aclose()
    asyncio.run(case())


def test_server_ping_id_does_not_collide_with_client_pending_id():
    async def case():
        c=MCPClient(config());future=asyncio.get_running_loop().create_future();c._pending[1]=future
        reply=c._deliver({'jsonrpc':'2.0','id':1,'method':'ping'})
        assert reply=={'jsonrpc':'2.0','id':1,'result':{}}
        assert not future.done()
        future.cancel();c._pending.clear();await c.aclose()
    asyncio.run(case())


def test_http_sse_server_ping_reply_unblocks_initialization():
    async def case():
        acknowledged=asyncio.Event()
        async def handler(reader,writer):
            head=(await reader.readuntil(b'\r\n\r\n')).decode()
            length=int(next(x.split(':',1)[1] for x in head.split('\r\n') if x.lower().startswith('content-length:')))
            q=json.loads(await reader.readexactly(length))
            if 'method' not in q:
                assert q['result']=={};acknowledged.set()
                writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n')
            elif q['method']=='initialize':
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: '+json.dumps({'jsonrpc':'2.0','id':q['id'],'method':'ping'}).encode()+b'\n\n');await writer.drain()
                try:await asyncio.wait_for(acknowledged.wait(),.5)
                except asyncio.TimeoutError:pass
                r={'protocolVersion':'2025-06-18','capabilities':{}}
                writer.write(b'data: '+json.dumps({'jsonrpc':'2.0','id':q['id'],'result':r}).encode()+b'\n\n')
            elif q['method']=='notifications/initialized':
                writer.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n')
            else:
                b=json.dumps({'jsonrpc':'2.0','id':q['id'],'result':{'tools':[]}}).encode()
                writer.write(f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(b)}\r\n\r\n'.encode()+b)
            await writer.drain();writer.close();await writer.wait_closed()
        srv=await asyncio.start_server(handler,'127.0.0.1',0)
        try:
            c=MCPClient(config(transport='http',url=f'http://127.0.0.1:{srv.sockets[0].getsockname()[1]}/mcp'))
            assert await c.list_tools()==[]
            assert acknowledged.is_set()
            await c.aclose()
        finally:srv.close();await srv.wait_closed()
    asyncio.run(case())
