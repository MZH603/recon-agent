"""Ephemeral, one-client authenticated loopback transport for the local Pi UI."""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

FRAME_LIMIT = 65536
PI_DIR = Path(__file__).with_name('pi')


class ProtocolError(ConnectionError):
    pass


def child_environment(port, token, source=None):
    source = os.environ if source is None else source
    allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP',
               'TERM', 'COLORTERM', 'TERM_PROGRAM', 'TERM_PROGRAM_VERSION', 'LANG',
               'LC_ALL', 'LC_CTYPE', 'WT_SESSION', 'WT_PROFILE_ID', 'HOME', 'USERPROFILE', 'NO_COLOR'}
    env = {k: v for k, v in source.items() if k.upper() in allowed}
    env.update(RECON_PI_PORT=str(port), RECON_PI_TOKEN=token)
    return env


def pi_available():
    node = shutil.which('node')
    if not node:
        return False, '需要 Node.js >=22.19.0'
    if not (PI_DIR / 'node_modules/@earendil-works/pi-tui/package.json').is_file():
        return False, f'请在 {PI_DIR} 执行 npm ci --ignore-scripts'
    try:
        probe = subprocess.run([node, '--input-type=module', '-e',
            "import '@earendil-works/pi-tui';console.log(process.versions.node)"],
            cwd=PI_DIR, env=child_environment(0, ''), capture_output=True, text=True, timeout=5)
        version = tuple(map(int, probe.stdout.strip().split('.')))
        if probe.returncode or version < (22, 19, 0):
            raise ValueError('Unsupported runtime')
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return False, f'需要 Node.js >=22.19.0 和完整 Pi 安装；请在 {PI_DIR} 执行 npm ci --ignore-scripts'
    return True, ''


async def read_frame(reader):
    try:
        line = await reader.readline()
        if not line:
            raise EOFError('Pi frontend disconnected')
        if len(line) > FRAME_LIMIT or not line.endswith(b'\n'):
            raise ProtocolError('Invalid frame length')
        value = json.loads(line.decode('utf-8'))
        if not isinstance(value, dict):
            raise ProtocolError('Expected object')
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError('Malformed frame') from exc


class PiBridge:
    """Bounded sync observer queue; socket writes always have a drain deadline."""
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.connected = asyncio.Event()
        self.disconnected = asyncio.Event()
        self.reader = self.writer = self.server = None
        self.handlers = set()
        self.queue = asyncio.Queue(maxsize=128)
        self.coalesced = {}
        self.pump = None

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._accept, '127.0.0.1', 0, limit=FRAME_LIMIT)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self.handlers.add(task)
        accepted = False
        try:
            if len(self.handlers) > 8 or self.connected.is_set():
                return
            hello = await asyncio.wait_for(read_frame(reader), 5)
            if (set(hello) != {'type', 'token'} or hello['type'] != 'hello' or
                    not isinstance(hello['token'], str) or
                    not hello['token'].isascii() or
                    not hmac.compare_digest(hello['token'].encode('ascii'), self.token.encode('ascii'))):
                return
            if self.connected.is_set():
                return
            self.reader, self.writer = reader, writer
            accepted = True
            self.connected.set()
            self.server.close()  # Wrong credentials must never close the listener.
            self.pump = asyncio.create_task(self._pump())
        except (ConnectionError, EOFError, asyncio.TimeoutError):
            pass
        finally:
            self.handlers.discard(task)
            if not accepted:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def wait_connected(self, timeout=10):
        await asyncio.wait_for(self.connected.wait(), timeout)

    async def receive(self):
        try:
            command = await read_frame(self.reader)
            kind = command.get('type')
            allowed = {'input': {'type', 'text'}, 'cancel': {'type', 'exit'},
                       'quit': {'type'}, 'status': {'type'}, 'report': {'type'},
                       'stop': {'type'}, 'abort': {'type'}}
            if not isinstance(kind, str) or kind not in allowed or set(command) != allowed[kind]:
                raise ProtocolError('Unknown command or forbidden fields')
            if kind == 'input' and (not isinstance(command['text'], str) or len(command['text']) > 16000):
                raise ProtocolError('Invalid input')
            if kind == 'cancel' and not isinstance(command['exit'], bool):
                raise ProtocolError('Invalid cancellation')
            return command
        except (ConnectionError, EOFError):
            self.disconnected.set()
            raise

    async def receive_setup(self):
        """Separate phase: runtime commands never accept connection/authorization."""
        from cli.launcher import LIMITS, SETUP_FIELDS, valid_text
        try:
            command = await read_frame(self.reader)
            if command == {'type': 'quit'} or command == {'type': 'cancel'}:
                return command
            if (set(command) != SETUP_FIELDS or command.get('type') != 'configure' or
                    type(command.get('authorized')) is not bool or
                    not all(valid_text(command[k], k, empty=True) for k in LIMITS)):
                raise ProtocolError('Invalid setup command')
            return command
        except (ConnectionError, EOFError):
            self.disconnected.set()
            raise

    async def send(self, event):
        data = (json.dumps(event, ensure_ascii=False) + '\n').encode('utf-8')
        if len(data) > FRAME_LIMIT:
            raise ProtocolError('Outbound frame too large')
        self.writer.write(data)
        await asyncio.wait_for(self.writer.drain(), 2)

    def emit(self, event):
        if self.disconnected.is_set():
            return
        key = (event['type'], event.get('id'), event.get('offset', 0)) if event['type'] in ('preview', 'activity') else None
        if key is not None and key in self.coalesced:
            self.coalesced[key] = event
            return
        try:
            self.queue.put_nowait(key if key else event)
            if key:
                self.coalesced[key] = event
        except asyncio.QueueFull:
            self.disconnected.set()  # Never block the graph callback or grow memory.

    async def _pump(self):
        try:
            while True:
                item = await self.queue.get()
                try:
                    await self.send(self.coalesced.pop(item) if isinstance(item, tuple) else item)
                finally:
                    self.queue.task_done()
        except (ConnectionError, asyncio.TimeoutError):
            self.disconnected.set()

    async def flush(self):
        await asyncio.wait_for(self.queue.join(), 2)

    async def __aexit__(self, *args):
        self.disconnected.set()
        if self.server:
            self.server.close()
        for task in list(self.handlers):
            task.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        if self.pump:
            self.pump.cancel()
            await asyncio.gather(self.pump, return_exceptions=True)
        if self.writer:
            self.writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.writer.wait_closed(), 2)
        if self.server:
            await self.server.wait_closed()
