"""Bounded, lazy MCP JSON-RPC connectors for explicitly trusted configurations.

Connectors are not an operating-system sandbox. Tool calls are never retried:
transport failure may mean the remote side effect already happened.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import ssl
import socket
from urllib.parse import urljoin, urlsplit

from platforms.subprocess import kill_and_reap, spawn_owned

PROTOCOL_VERSION = '2025-06-18'


class MCPError(RuntimeError):
    """Safe public message with optional bounded raw envelope for local evidence."""

    def __init__(self, message, *, response=None, outcome_unknown=False):
        super().__init__(message)
        self.response = response
        self.outcome_unknown = outcome_unknown


class MCPClient:
    def __init__(self, config):
        self.config = config
        self.process = None
        self._initialized = False
        self._closed = False
        self._lock = asyncio.Lock()
        self._next_id = 0
        self._pending = {}
        self._sent_calls = set()
        self._tasks = []
        self._writers = set()
        self._session_id = None
        self._protocol = PROTOCOL_VERSION
        self._sse_url = None
        self._endpoint_future = None
        self._tools = None

    @property
    def limit(self):
        return min(self.config.max_output_bytes, 2097152 - 4096)  # Reserve local evidence envelope overhead.

    async def _bounded(self, operation):
        if self._closed:
            operation.close()
            raise MCPError('MCP connector is closed; no automatic reconnect')
        try:
            return await asyncio.wait_for(operation, self.config.timeout_seconds)
        except asyncio.CancelledError:
            await self.aclose()
            raise
        except Exception as exc:
            await self.aclose()
            if isinstance(exc, MCPError):
                raise
            if isinstance(exc, asyncio.TimeoutError):
                raise MCPError('MCP operation timed out; remote outcome may be unknown') from None
            raise MCPError('MCP transport or protocol failure; remote outcome may be unknown') from None

    async def list_tools(self):
        async with self._lock:
            return await self._bounded(self._list_tools())

    async def _list_tools(self):
        await self._initialize()
        if self._tools is not None:
            return self._tools
        tools, cursors, cursor = [], set(), None
        for _ in range(100):
            result = await self._rpc('tools/list', {'cursor': cursor} if cursor is not None else {})
            page = result.get('tools')
            if not isinstance(page, list) or any(not isinstance(t, dict) or not isinstance(t.get('name'), str) or not isinstance(t.get('inputSchema'), dict) for t in page):
                raise MCPError('Invalid MCP tools/list response')
            tools.extend(page)
            if len(json.dumps(tools, ensure_ascii=False).encode()) > self.limit:
                raise MCPError('MCP discovery exceeds output limit')
            cursor = result.get('nextCursor')
            if cursor is None:
                if len({t['name'] for t in tools}) != len(tools):
                    raise MCPError('Duplicate remote tool names')
                self._tools = tools
                return tools
            if not isinstance(cursor, str) or cursor in cursors:
                raise MCPError('Invalid or repeated MCP pagination cursor')
            cursors.add(cursor)
        raise MCPError('MCP discovery page limit exceeded')

    async def call_tool(self, name, arguments):
        async with self._lock:
            return await self._bounded(self._call_tool(name, arguments))

    async def _call_tool(self, name, arguments):
        await self._initialize()
        return await self._rpc('tools/call', {'name': name, 'arguments': arguments})

    async def _initialize(self):
        if self._initialized:
            return
        if self.config.transport == 'stdio':
            env = {k: v for k, v in os.environ.items() if k.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
            for child, parent in self.config.env.items():
                if parent not in os.environ:
                    raise MCPError('Configured MCP environment variable is missing')
                env[child] = os.environ[parent]
            self.process = await spawn_owned(
                self.config.command, *self.config.args, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=env, limit=max(self.limit + 1, 1024))
            self._tasks.append(asyncio.create_task(self._stdio_reader()))
            self._tasks.append(asyncio.create_task(self._drain_stderr()))
        elif self.config.transport == 'sse':
            self._endpoint_future = asyncio.get_running_loop().create_future()
            self._tasks.append(asyncio.create_task(self._legacy_reader()))
            self._sse_url = await self._endpoint_future
        elif self.config.transport != 'http':
            raise MCPError('Unsupported MCP transport')
        result = await self._rpc('initialize', {
            'protocolVersion': PROTOCOL_VERSION, 'capabilities': {},
            'clientInfo': {'name': 'recon-agent', 'version': '1.0.0'}})
        version = result.get('protocolVersion')
        if version not in {'2025-06-18', '2025-03-26', '2024-11-05'}:
            raise MCPError('Unsupported negotiated MCP protocol version')
        if not isinstance(result.get('capabilities'), dict):
            raise MCPError('Invalid MCP initialization capabilities')
        self._protocol = version
        await self._rpc('notifications/initialized', None, notification=True)
        self._initialized = True

    def _deliver(self, message):
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            raise MCPError('Invalid MCP JSON-RPC message')
        ident = message.get('id')
        if 'method' in message:
            # Request IDs belong to independent directions and may collide.
            if ident is None:
                return None
            return {'jsonrpc':'2.0', 'id':ident, 'result':{}} if message['method'] == 'ping' else {
                'jsonrpc':'2.0', 'id':ident, 'error':{'code':-32601, 'message':'Method not supported'}}
        future = self._pending.get(ident)
        if future and not future.done():
            if 'error' in message:
                future.set_exception(MCPError('Remote MCP JSON-RPC error', response=message))
            elif isinstance(message.get('result'), dict):
                future.set_result(message['result'])
            else:
                future.set_exception(MCPError('Invalid MCP response result'))
        return None

    def _fail_pending(self):
        for ident, f in list(self._pending.items()):
            if not f.done():
                f.set_exception(MCPError('MCP connection ended before response',
                                         outcome_unknown=ident in self._sent_calls))
        if self._endpoint_future and not self._endpoint_future.done():
            self._endpoint_future.set_exception(MCPError('MCP connection ended before endpoint'))

    async def _stdio_reader(self):
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                if len(line) > self.limit:
                    raise MCPError('MCP response exceeds output limit')
                reply = self._deliver(json.loads(line.decode('utf-8')))
                if reply:
                    self.process.stdin.write(json.dumps(reply).encode() + b'\n')
                    await self.process.stdin.drain()
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            self._fail_pending()

    async def _drain_stderr(self):
        while await self.process.stderr.read(4096):
            pass  # Never retain or expose credential-bearing server diagnostics.

    async def _rpc(self, method, params, notification=False):
        self._next_id += 1
        ident = self._next_id
        message = {'jsonrpc': '2.0', 'method': method}
        if params is not None:
            message['params'] = params
        if not notification:
            message['id'] = ident
            self._pending[ident] = asyncio.get_running_loop().create_future()
        sent = False
        def mark_sent():
            nonlocal sent
            sent = True
            if method == 'tools/call':
                self._sent_calls.add(ident)
        try:
            data = json.dumps(message, ensure_ascii=False).encode('utf-8')
            if len(data) > self.limit:
                raise MCPError('MCP request exceeds output limit')
            if self.config.transport == 'stdio':
                mark_sent()
                self.process.stdin.write(data + b'\n')
                await self.process.stdin.drain()
            else:
                url = self._sse_url if self.config.transport == 'sse' else self.config.url
                async with self._http('POST', url, data, on_sent=mark_sent) as response:
                    status, headers, body = response
                    if status not in {200, 202, 204}:
                        raise MCPError('MCP HTTP request rejected; remote outcome may be unknown')
                    if 'mcp-session-id' in headers:
                        session = headers['mcp-session-id']
                        if not session or any(ord(c) < 33 or ord(c) > 126 for c in session):
                            raise MCPError('Invalid MCP session identifier')
                        if self._session_id and session != self._session_id:
                            raise MCPError('MCP session identifier changed')
                        self._session_id = session
                    if not notification and self.config.transport == 'http':
                        if status != 200:
                            raise MCPError('MCP request has no response')
                        if 'text/event-stream' in headers.get('content-type', ''):
                            async for event, text in self._events(body):
                                if event in {'message', ''}:
                                    reply = self._deliver(json.loads(text))
                                    if reply:
                                        await self._post_reply(reply, self.config.url)
                                    if self._pending[ident].done():
                                        break
                        elif 'application/json' in headers.get('content-type', ''):
                            chunks = [chunk async for chunk in body]
                            self._deliver(json.loads(b''.join(chunks).decode('utf-8')))
                        else:
                            raise MCPError('Unsupported MCP response content type')
                        if not self._pending[ident].done():
                            raise MCPError('MCP response ID mismatch or missing result')
            if not notification:
                return await self._pending[ident]
            return None
        except MCPError as exc:
            if method == 'tools/call' and sent and exc.response is None:
                exc.outcome_unknown = True
            raise
        except Exception:
            raise MCPError('MCP transport or protocol failure',
                           outcome_unknown=method == 'tools/call' and sent) from None
        finally:
            self._sent_calls.discard(ident)
            future = self._pending.pop(ident, None)
            if future and not future.done():
                future.cancel()
            elif future and not future.cancelled():
                future.exception()  # Mark errors retrieved even on a transport failure.

    async def _post_reply(self, reply, url):
        data = json.dumps(reply, ensure_ascii=False).encode('utf-8')
        if len(data) > self.limit:
            raise MCPError('MCP server request reply exceeds output limit')
        async with self._http('POST', url, data) as response:
            if response[0] not in {200, 202, 204}:
                raise MCPError('MCP server request reply rejected')

    @contextlib.asynccontextmanager
    async def _http(self, method, url, data=b'', on_sent=None):
        u = urlsplit(url)
        if u.scheme not in {'http', 'https'} or not u.hostname or u.username or u.password or u.fragment:
            raise MCPError('Invalid MCP connector HTTP URL')
        from platforms.sync_worker import resolve_addresses
        port = u.port or (443 if u.scheme == 'https' else 80)
        addresses = await resolve_addresses(u.hostname, port)
        if not addresses: raise MCPError('MCP hostname has no resolved address')
        reader, writer = await asyncio.open_connection(
            addresses[0][4][0], port,
            ssl=ssl.create_default_context() if u.scheme == 'https' else None,
            server_hostname=u.hostname if u.scheme == 'https' else None, limit=max(self.limit + 1, 16384))
        self._writers.add(writer)
        try:
            host = f'[{u.hostname}]' if ':' in u.hostname else u.hostname
            if u.port:
                host += f':{u.port}'
            headers = {'Host':host,'Accept':'application/json, text/event-stream',
                       'Content-Type':'application/json', 'Content-Length':str(len(data)), 'Connection':'close'}
            if self._initialized:
                headers['MCP-Protocol-Version'] = self._protocol
            if self._session_id:
                headers['Mcp-Session-Id'] = self._session_id
            for name, env_name in self.config.headers_env.items():
                value = os.environ.get(env_name)
                if value is None:
                    raise MCPError('Configured MCP header environment variable is missing')
                if name.lower() in {'host','accept','content-type','content-length','connection','mcp-session-id','mcp-protocol-version'}:
                    raise MCPError('Configured MCP header overrides protocol header')
                headers[name] = value
            if any('\r' in k + v or '\n' in k + v or ':' in k for k,v in headers.items()):
                raise MCPError('Invalid MCP HTTP header')
            path = u.path or '/'
            if u.query:
                path += '?' + u.query
            if any(c.isspace() for c in path):
                raise MCPError('Invalid MCP HTTP request path')
            request = f'{method} {path} HTTP/1.1\r\n' + ''.join(f'{k}: {v}\r\n' for k,v in headers.items()) + '\r\n'
            if on_sent is not None:
                on_sent()
            writer.write(request.encode('utf-8') + data)
            await writer.drain()
            raw = await reader.readuntil(b'\r\n\r\n')
            if len(raw) > 16384:
                raise MCPError('MCP HTTP headers exceed limit')
            lines = raw.decode('iso-8859-1').split('\r\n')
            status = int(lines[0].split()[1])
            response_headers = {}
            for line in lines[1:]:
                if ':' in line:
                    k,v = line.split(':',1)
                    response_headers[k.lower()] = v.strip()
            yield status, response_headers, self._body(reader, response_headers, bounded=not (method == 'GET' and self.config.transport == 'sse'))
        finally:
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _body(self, reader, headers, bounded=True):
        total = 0
        remaining = int(headers['content-length']) if 'content-length' in headers else None
        if remaining is not None and (remaining < 0 or (bounded and remaining > self.limit)):
            raise MCPError('MCP response exceeds output limit')
        chunked = headers.get('transfer-encoding', '').lower() == 'chunked'
        while remaining is None or remaining > 0:
            if chunked:
                line = await reader.readline()
                if len(line) > 1024:
                    raise MCPError('MCP chunk header exceeds limit')
                size = int(line.split(b';')[0],16)
                if size == 0:
                    return
                if size < 0 or size > (self.limit - total if bounded else self.limit):
                    raise MCPError('MCP response exceeds output limit')
                chunk = await reader.readexactly(size)
                if await reader.readexactly(2) != b'\r\n':
                    raise MCPError('Invalid MCP HTTP chunk')
            else:
                chunk = await reader.read(min(4096, remaining) if remaining is not None else 4096)
            if not chunk:
                if remaining:
                    raise MCPError('Incomplete MCP HTTP body')
                return
            total += len(chunk)
            if bounded and total > self.limit:
                raise MCPError('MCP response exceeds output limit')
            if remaining is not None:
                remaining -= len(chunk)
            yield chunk

    async def _events(self, body):
        buffer, event, data, size = b'', '', [], 0
        async for chunk in body:
            buffer += chunk
            while b'\n' in buffer:
                raw, buffer = buffer.split(b'\n',1)
                size += len(raw) + 1
                if size > self.limit:
                    raise MCPError('MCP SSE event exceeds output limit')
                line = raw.rstrip(b'\r').decode('utf-8')
                if not line:
                    if data:
                        yield event, '\n'.join(data)
                    event, data, size = '', [], 0
                elif line.startswith('event:'):
                    event = line[6:].lstrip(' ')
                elif line.startswith('data:'):
                    data.append(line[5:].lstrip(' '))
            if len(buffer) > self.limit:
                raise MCPError('MCP SSE event exceeds output limit')

    async def _legacy_reader(self):
        try:
            async with self._http('GET', self.config.url) as response:
                status, headers, body = response
                if status != 200 or 'text/event-stream' not in headers.get('content-type',''):
                    raise MCPError('Invalid legacy MCP SSE response')
                async for event, text in self._events(body):
                    if event == 'endpoint':
                        endpoint = urljoin(self.config.url, text)
                        if urlsplit(endpoint)[:2] != urlsplit(self.config.url)[:2]:
                            raise MCPError('Legacy MCP endpoint changes connector origin')
                        if not self._endpoint_future.done():
                            self._endpoint_future.set_result(endpoint)
                    elif event in {'message',''}:
                        reply = self._deliver(json.loads(text))
                        if reply:
                            await self._post_reply(reply, self._sse_url)
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            self._fail_pending()

    async def aclose(self):
        if self._closed:
            return
        self._closed = True
        if self._session_id and self.config.transport == 'http':
            async def delete_session():
                async with self._http('DELETE', self.config.url):
                    pass
            with contextlib.suppress(Exception):
                await asyncio.wait_for(delete_session(), min(self.config.timeout_seconds, 1))
        for writer in list(self._writers):
            writer.close()
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._fail_pending()
        if self.process is not None:
            await kill_and_reap(self.process)
