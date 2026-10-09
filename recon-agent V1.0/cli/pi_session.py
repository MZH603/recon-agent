"""Pi presentation around the original Python-owned durable session runtime."""
from __future__ import annotations

import asyncio
import contextlib
import io
import hashlib
from pathlib import Path
import shutil
import sys
import shlex
from uuid import uuid4

from rich.console import Console
from cli.pi_bridge import PI_DIR, PiBridge, ProtocolError, child_environment, pi_available
from cli.progress import SessionProgress, safe_text, visible_content
from cli.session import LazyLLM, session_prompt
from core.orchestration import SessionRuntime
from gate.scan_gate import ScanGate


class PiProgress(SessionProgress):
    def __init__(self, bridge):
        super().__init__(is_tty=False)
        self.bridge, self.turn = bridge, 0
        self.plan_shown = None

    def _flush_line(self):
        self.line = ''

    def _note(self, text):
        self.bridge.emit({'type': 'note', 'text': safe_text(text)[:12000]})

    def _preview(self, key, value):
        slot = self.slots[key]
        if value.startswith(slot.get('shown', '')) and value != slot.get('shown'):
            previous = len(slot.get('shown', ''))
            slot['shown'] = value
            self.publish(f'{self.turn}:{key}', value, start=previous // 6000 * 6000)

    def publish(self, identifier, value, start=0):
        # Offsets are segment keys in Unicode codepoints; JS joins ordered segments,
        # rather than slicing UTF-16 strings at Python offsets.
        for offset in range(start, len(value), 6000):
            self.bridge.emit({'type': 'preview', 'id': identifier, 'offset': offset,
                             'text': value[offset:offset + 6000]})

    def __call__(self, event):
        if event['kind'] == 'model_start':
            self.turn += 1
        super().__call__(event)
        self.bridge.emit({'type': 'activity', 'text': safe_text(self.label)})


class EventStream(io.TextIOBase):
    """Capture plain/Rich logger output without forwarding raw terminal controls."""
    def __init__(self, bridge):
        self.bridge, self.pending = bridge, ''

    def write(self, text):
        self.pending += safe_text(text)
        while '\n' in self.pending or len(self.pending) > 12000:
            if '\n' in self.pending[:12001]:
                line, self.pending = self.pending.split('\n', 1)
            else:
                line, self.pending = self.pending[:12000], self.pending[12000:]
            if line:
                self.bridge.emit({'type': 'note', 'text': line})
        return len(text)

    def flush(self):
        if self.pending:
            self.bridge.emit({'type': 'note', 'text': self.pending})
            self.pending = ''


@contextlib.contextmanager
def capture_logs(bridge):
    from utils import logger
    stream = EventStream(bridge)
    previous = logger._console
    try:
        logger._console = Console(file=stream, force_terminal=False, no_color=True, highlight=False)
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            yield
    finally:
        stream.flush()
        logger._console = previous


def display_state(state, gate, progress):
    result = {'type': 'state', 'status': safe_text(state.get('status', 'idle')),
              'level': gate.current_level(), 'decisions': state.get('decisions', 0),
              'actions': state.get('actions', 0), 'used_tokens': state.get('used_tokens', 0)}
    if state.get('plan'):
        plan = visible_content(str(state['plan']))
        if len(plan.encode('utf-8')) <= 2000:
            result['plan'] = plan
        elif progress.plan_shown != plan:
            progress._note('计划（模型建议，未验证）:')
            progress.publish('saved-plan:' + hashlib.sha256(plan.encode('utf-8')).hexdigest(), plan)
            progress.plan_shown = plan
    pending = state.get('pending')
    if pending:
        question = visible_content(str(pending.get('question', '')))
        shown = progress.was_shown(question)
        if len(question.encode('utf-8')) > 8000 and not shown:
            progress.publish(f'question:{progress.turn}', question)
            progress.shown.add(question)
            shown = True
        result['pending'] = {'kind': safe_text(pending.get('kind', '')),
                             'question': '' if shown else question,
                             'options': [visible_content(str(x))[:256] +
                                ('…' if len(visible_content(str(x))) > 256 else '')
                                for x in pending.get('options', [])[:20]]}
        if len(pending.get('options', [])) > 20:
            result['pending']['options'].append('…更多选项未展开')
        if pending.get('kind') == 'clarification':
            latest = next((m.get('content', '') for m in reversed(state.get('messages', []))
                           if m.get('role') == 'assistant'), '')
            if latest and not progress.was_shown(latest):
                result['answer'] = visible_content(latest)
    elif state.get('answer'):
        answer = state['answer']
        if not (progress.was_shown(answer) or progress.was_shown(answer.removesuffix(' [无证据]'))):
            result['answer'] = visible_content(answer)
    if len(result.get('answer', '').encode('utf-8')) > 8000:
        progress.publish(f'answer:{progress.turn}', result.pop('answer'))
    return result


async def serve_runtime(runtime, gate, bridge, report=None):
    """Input stays responsive while one graph task runs; cancellation awaits durability."""
    progress = PiProgress(bridge)
    active = None
    exit_code = 0

    async def cancel():
        nonlocal active
        if active:
            active.cancel()
            await asyncio.gather(active, return_exceptions=True)
            active = None
        runtime.on_event = None

    async def execute(text):
        runtime.on_event = progress
        try:
            state = await runtime.state()
            state = await (runtime.resume(text) if state.get('pending') else runtime.submit(text))
            bridge.emit(display_state(state, gate, progress))
        except asyncio.CancelledError:
            raise
        except Exception:
            bridge.emit({'type': 'note', 'text': '任务未完成，请检查状态并显式恢复。'})
            bridge.emit(display_state(await runtime.state(), gate, progress))
        finally:
            runtime.on_event = None

    receive = None
    lost = asyncio.create_task(bridge.disconnected.wait())
    try:
        bridge.emit(display_state(await runtime.state(), gate, progress))
        while True:
            receive = asyncio.create_task(bridge.receive())
            done, _ = await asyncio.wait({receive, lost}, return_when=asyncio.FIRST_COMPLETED)
            if lost in done:
                exit_code = 2
                break
            command = receive.result()
            kind = command['type']
            text = command.get('text', '').strip()
            if kind == 'input':
                aliases = {'状态': 'status', '报告': 'report', '生成报告': 'report', 'exit': 'quit', '退出': 'quit'}
                kind = aliases.get(text.lower(), text.lower()) if text.lower() in (
                    '状态', '报告', '生成报告', 'exit', '退出', 'status', 'report', 'stop', 'abort', 'quit') else kind
            if kind in ('quit', 'cancel'):
                await cancel()
                if kind == 'quit' or command.get('exit'):
                    exit_code = 130 if kind == 'cancel' else 0
                    break
                bridge.emit(display_state(await runtime.state(), gate, progress))
            elif kind in ('stop', 'abort'):
                await cancel()  # runtime.stop itself needs the graph's lock.
                state = await runtime.stop(abort=kind == 'abort')
                bridge.emit(display_state(state, gate, progress))
            elif kind == 'status':
                event = display_state(await runtime.state(), gate, progress)
                event['busy'] = bool(active and not active.done())
                if event['busy']:
                    event['status'] = 'running'
                    event.pop('pending', None)
                    event.pop('answer', None)
                bridge.emit(event)
            elif kind == 'report':
                if report:
                    report(await runtime.state())
            elif kind == 'input' and text:
                if active and not active.done():
                    bridge.emit({'type': 'note', 'text': '任务运行中；可输入 stop、abort 或 quit。'})
                else:
                    bridge.emit({'type': 'activity', 'text': '等待模型'})
                    active = asyncio.create_task(execute(text))
    except (EOFError, ConnectionError):
        exit_code = 2
    finally:
        if receive and not receive.done():
            receive.cancel()
        lost.cancel()
        await asyncio.gather(*(t for t in (receive, lost) if t), return_exceptions=True)
        await cancel()
        if report:
            state = await runtime.state()
            if state.get('events') or state.get('pending') or state.get('executions'):
                report(state)
        if not bridge.disconnected.is_set():
            bridge.emit({'type': 'shutdown', 'code': exit_code})
            with contextlib.suppress(ConnectionError, asyncio.TimeoutError):
                await bridge.flush()
    return exit_code


async def close_child(child, timeout=3):
    """Allow normal terminal restoration first, then force-kill a hung frontend."""
    if child.returncode is None:
        try:
            await asyncio.wait_for(child.wait(), timeout)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                child.kill()  # SIGTERM handlers may keep a POSIX Node process alive.
            await child.wait()


async def run_pi_session(target, settings, batch, is_tty, requested_level, model_override,
                         output_format, output_dir, run_pipeline=None, *, resume_id=None,
                         session_id=None, llm_factory=None, connection_override=None):
    from platforms.paths import get_config_dir
    from tools.registry import build_default
    from output.session_report import save_session_report
    from utils.logger import err, ok, warn
    available, reason = pi_available()
    if not available or not is_tty or batch:
        err('Pi 界面不可用: ' + (reason or '需要交互终端'))
        return 2
    if output_format not in ('markdown', 'json', 'csv'):
        err('报告格式必须为 markdown/json/csv')
        return 2
    identifier = resume_id or session_id or uuid4().hex
    gate = ScanGate(target, batch_mode=batch, is_tty=is_tty, requested_level=0)
    registry = build_default(settings, gate, target)
    runtime = SessionRuntime(target=target, registry=registry,
        llm=LazyLLM(settings, model_override, llm_factory, connection_override=connection_override), gate=gate, settings=settings,
        db_path=get_config_dir() / 'agent_state.sqlite', session_id=identifier,
        system_prompt=session_prompt(registry, target), require_existing=bool(resume_id))
    child = None
    unexpected_disconnect = False
    try:
        async with runtime, PiBridge() as bridge:
            child = await asyncio.create_subprocess_exec(shutil.which('node'), str(PI_DIR / 'app.mjs'),
                env=child_environment(bridge.port, bridge.token))  # inherit the original terminal
            connection = asyncio.create_task(bridge.wait_connected())
            exited = asyncio.create_task(child.wait())
            try:
                done, _ = await asyncio.wait({connection, exited}, return_when=asyncio.FIRST_COMPLETED)
                if exited in done:
                    return 2
                await connection
            finally:
                for task in (connection, exited):
                    task.cancel()
                await asyncio.gather(connection, exited, return_exceptions=True)
            def report(state):
                paths = save_session_report(state, gate.current_level(), output_format,
                    Path(output_dir) if output_dir else None)
                ok(f"报告已生成: {paths['selected']}")
            with capture_logs(bridge):
                bridge.emit({'type': 'note', 'text': f'会话 ID: {safe_text(identifier)} · 当前 L0，等待任务。'})
                bridge.emit({'type': 'note', 'text': '恢复命令: recon-agent --session --resume ' +
                    shlex.quote(safe_text(identifier)) + ' -t ' + shlex.quote(safe_text(target)) + ' --authorized'})
                bridge.emit({'type': 'note', 'text': '命令: status · report · stop · abort · quit；Shift+Enter 换行'})
                result = await serve_runtime(runtime, gate, bridge, report)
                unexpected_disconnect = result == 2
            return result
    except (ValueError, RuntimeError, OSError, asyncio.TimeoutError):
        err('Pi 会话无法打开，请检查本地 Node/Pi 安装与会话 ID。')
        return 2
    finally:
        if child:
            await close_child(child)
        if unexpected_disconnect:
            # Both capture_logs and the child terminal have closed before Python prints.
            warn('Pi 界面意外断开，任务已取消并保留用量。恢复命令: recon-agent --session --resume ' +
                 shlex.quote(safe_text(identifier)) + ' -t ' + shlex.quote(safe_text(target)) + ' --authorized')
