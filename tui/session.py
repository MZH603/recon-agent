"""TUI presentation around the original Python-owned durable session runtime."""
from __future__ import annotations

import asyncio
import contextlib
import io
import hashlib
from pathlib import Path
import shutil
import sys
import shlex
import os

from rich.console import Console
from tui.bridge import TUI_DIR, TuiBridge, ProtocolError, child_environment, tui_available
from agent.cli.progress import CONTEXT_FIELDS, SessionProgress, safe_text, visible_content
from agent.core.session_factory import create_session_runtime


class TuiProgress(SessionProgress):
    def __init__(self, bridge):
        super().__init__(is_tty=False)
        self.bridge, self.turn = bridge, 0
        self.plan_shown = None
        self.task_id = None
        self.pending_preview_key = None
        self.llm = None
        self.model_label = self.primary_model_label = ''
        self.model_fallback = False
        from agent.tools.runtime.result_payload import ResultPayloads
        from agent.utils.config import Settings
        self.display_payloads = ResultPayloads(Settings(TOOL_RESULT_MAX_BYTES=16000))

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
        if event['kind'] == 'context':
            self.bridge.emit({'type': 'context', **{key: event[key] for key in CONTEXT_FIELDS if key in event}})
            return
        if event['kind'] == 'model_start':
            self.turn += 1
            self.model_fallback = False
            self.model_label = self.primary_model_label
        if event['kind'] == 'fallback':
            from agent.utils.display import display_text
            name = getattr(event.get('delta'), 'name', '')
            if name:
                self.model_label = display_text(name, 128)
                self.model_fallback = True
        elif event['kind'] in ('model_start', 'delta', 'retry', 'model_end') and not self.model_fallback:
            # The lazy service may now exist. Its constructed provider order
            # excludes missing credentials and resolves configured aliases.
            provider = getattr(getattr(self.llm, 'service', None), 'provider', None)
            names = getattr(provider, '_names', ())
            if names:
                from agent.utils.display import display_text
                self.model_label = display_text(names[0], 128)
        # Pi owns tool entries; plain CLI's printed summaries would
        # otherwise duplicate the same tool result in the conversation.
        if event['kind'] == 'tool_end':
            self.label = '工具已返回，继续处理'
        elif event['kind'] == 'tool_start':
            self.label = f"工具 {safe_text(event['name'])} 执行中"
        else:
            super().__call__(event)
        if event['kind'] in ('tool_start','tool_wait','tool_end','tool_cancelled','tool_late'):
            def clean(value):
                if isinstance(value,str): return safe_text(value)
                if isinstance(value,list): return [clean(v) for v in value]
                if isinstance(value,dict): return {k:clean(v) for k,v in value.items()}
                return value
            payload=clean({k:v for k,v in event.items() if k!='kind'})
            if isinstance(payload.get('result'),dict):
                payload['result']=self.display_payloads.for_model(payload['result'])
            self.bridge.emit({'type':'tool','phase':event['kind'],**payload})
        if event['kind'] != 'tool_late':
            self.bridge.emit({'type': 'activity', 'text': safe_text(self.label), 'model': self.model_label})


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
    from agent.utils import logger
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
    if state.get('task_id') != progress.task_id:
        progress.task_id=state.get('task_id')
        progress.plan_shown=None
        progress.pending_preview_key=None
        progress.shown.clear()
        progress.slots.clear()
    result = {'type': 'state', 'status': safe_text(state.get('status', 'idle')),
              'level': gate.current_level(), 'decisions': state.get('decisions', 0),
              'actions': state.get('actions', 0), 'used_tokens': state.get('used_tokens', 0)}
    for key in ('task_id','max_tokens','max_cost','used_cost','session_used_tokens','session_used_cost','usage_estimated_calls','cost_unknown_calls'):
        result[key]=state.get(key)
    result['model'] = getattr(progress, 'model_label', '')
    for key in CONTEXT_FIELDS:
        result[key] = state.get(key)
    result['result_count']=len(state.get('results',[]))
    result['results']=[{'execution_id':str(r.get('execution_id',''))[:64],'name':safe_text(r.get('name',''))[:128],
        'status':r.get('status','success' if r.get('success') else 'failure'),
        'summary':safe_text(r.get('summary',''))[:500], 'error':safe_text(r.get('error',''))[:600],
        'evidence':[safe_text(e)[:300] for e in r.get('evidence',[])[:5]],
        'artifacts':[{k:safe_text(str(a.get(k,'')))[:(2048 if k=='path' else 128)] for k in ('id','path','purpose')} for a in r.get('artifacts',[])[-2:]]}
        for r in state.get('results',[])[-10:]]
    import json
    while len(json.dumps(result['results'],ensure_ascii=False).encode())>24000:
        result['results'].pop(0)
    if state.get('plan'):
        plan = visible_content(str(state['plan']))
        if len(plan.encode('utf-8')) <= 2000:
            result['plan'] = plan
        else:
            result['plan'] = plan[:500] + '\n…完整计划见对话'
            if progress.plan_shown != plan:
                progress._note('计划（模型建议，未验证）:')
                progress.publish('saved-plan:' + hashlib.sha256(plan.encode('utf-8')).hexdigest(), plan)
                progress.plan_shown = plan
    pending = state.get('pending')
    if pending:
        question = visible_content(str(pending.get('question', '')))
        # Authorization is a new interaction even when its wording is identical.
        # Streaming answer de-duplication must not hide a renewed confirmation.
        interactive_auth = str(pending.get('kind','')).startswith('authorization')
        pending_key = (pending.get('interrupt_id') or pending.get('event_id'), question)
        shown = (progress.pending_preview_key == pending_key if interactive_auth
                 else progress.was_shown(question))
        if len(question.encode('utf-8')) > 8000 and not shown:
            identity = hashlib.sha256(str(pending_key).encode('utf-8')).hexdigest()
            progress.publish(f'question:{progress.turn}:{identity}', question)
            if interactive_auth: progress.pending_preview_key=pending_key
            else: progress.shown.add(question)
            shown = True
        result['pending'] = {'kind': safe_text(pending.get('kind', '')),
                             'interrupt_id':safe_text(pending.get('interrupt_id','')),
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
    progress = TuiProgress(bridge)
    # Configuration only: never construct a provider, or serialize connection/key data.
    from agent.utils.display import display_text
    connection = getattr(runtime.llm, 'connection_override', None)
    configured = getattr(getattr(runtime.llm, 'settings', None), 'model', None)
    configured_name = getattr(runtime.llm, 'model', None) or os.environ.get('RECON_MODEL', '').strip() or getattr(configured, 'name', '')
    for endpoint in getattr(configured, 'custom_endpoints', []):
        if configured_name in (endpoint.get('name'), endpoint.get('model')):
            configured_name = endpoint.get('model') or configured_name
            break
    progress.model_label = display_text(getattr(connection, 'model', None) or
        getattr(getattr(runtime.llm, 'service', None), 'model_name', None) or
        configured_name or '未知', 128)
    progress.primary_model_label = progress.model_label
    progress.llm = runtime.llm
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
            from agent.cli.session_commands import operator_command, apply_command
            command=operator_command(text)
            state = await apply_command(runtime,command) if command else await (runtime.resume(text) if state.get('pending') else runtime.submit(text))
            bridge.emit(display_state(state, gate, progress))
        except asyncio.CancelledError:
            raise
        except ValueError as exc:
            bridge.emit({'type':'note','text':safe_text(str(exc))})
            bridge.emit(display_state(await runtime.state(),gate,progress))
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
                event['status_requested'] = True
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
                from agent.cli.session_commands import operator_command
                try: operator=operator_command(text)
                except ValueError as exc:
                    bridge.emit({'type':'note','text':safe_text(str(exc))})
                    continue
                if operator:
                    if operator[0]=='budget' and active and not active.done():
                        bridge.emit({'type':'note','text':'任务仍在运行，请在预算暂停后追加，或先 stop 保存当前进度。'})
                        continue
                    await cancel()
                    active=asyncio.create_task(execute(text))
                    continue
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


async def run_tui_session(target, settings, batch, is_tty, requested_level, model_override,
                         output_format, output_dir, run_pipeline=None, *, resume_id=None,
                         session_id=None, llm_factory=None, connection_override=None):
    from agent.output.session_report import save_session_report
    from agent.utils.logger import err, ok, warn
    available, reason = tui_available()
    if not available or not is_tty or batch:
        err('TUI 界面不可用: ' + (reason or '需要交互终端'))
        return 2
    if output_format not in ('markdown', 'json', 'csv'):
        err('报告格式必须为 markdown/json/csv')
        return 2
    try:
        runtime = create_session_runtime(target=target, settings=settings, batch=batch,
            is_tty=is_tty, model_override=model_override, resume_id=resume_id,
            session_id=session_id, llm_factory=llm_factory, connection_override=connection_override)
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        err('TUI 会话无法打开: ' + safe_text(str(exc)))
        return 2
    gate, identifier = runtime.gate, runtime.session_id
    child = None
    unexpected_disconnect = False
    try:
        async with runtime, TuiBridge() as bridge:
            env=child_environment(bridge.port,bridge.token)
            env['RECON_TUI_THEME']=settings.TUI_THEME
            child = await asyncio.create_subprocess_exec(shutil.which('node'), str(TUI_DIR / 'app.mjs'),
                env=env)  # inherit the original terminal
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
                bridge.emit({'type': 'note', 'text': '输入 / 查看命令；/help 查看帮助。Shift+Enter 换行。'})
                result = await serve_runtime(runtime, gate, bridge, report)
                unexpected_disconnect = result == 2
            return result
    except (ValueError, RuntimeError, OSError, ImportError, asyncio.TimeoutError) as exc:
        err('TUI 会话无法打开: ' + safe_text(str(exc)))
        return 2
    finally:
        if child:
            await close_child(child)
        if unexpected_disconnect:
            # Both capture_logs and the child terminal have closed before Python prints.
            warn('TUI 界面意外断开，任务已取消并保留用量。恢复命令: recon-agent --session --resume ' +
                 shlex.quote(safe_text(identifier)) + ' -t ' + shlex.quote(safe_text(target)) + ' --authorized')
