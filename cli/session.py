"""Idle-first durable sessions; synchronous input only while graph is idle."""
from __future__ import annotations
import shlex
import asyncio
from langgraph.errors import NodeCancelledError
from rich.markup import escape
from pathlib import Path
from core.session_factory import create_session_runtime
from core.prompts import session_prompt
from model.lazy import LazyLLM
from cli.progress import SessionProgress, safe_text
from utils.logger import info, ok, warn, err


def show_state(state, gate, progress=None):
    status = {'idle':'等待输入','running':'运行中','completed':'已完成','stopped':'已停止','aborted':'已停止','error':'异常暂停'}.get(state.get('status'),'等待输入')
    pending = state.get('pending') or {}
    if state.get('status') == 'paused':
        kind = pending.get('kind')
        status = {'budget': '费用预算暂停', 'context_limit': '上下文超限'}.get(kind) or ('等待授权' if kind in ('l1','l2_unlock','l2_action','authorization') else ('等待输入' if kind == 'ask_user' else '异常暂停'))
    info(f"状态: {status} · L{gate.current_level()}")
    tokens, capacity, trigger = (state.get(key) for key in ('context_tokens', 'context_capacity', 'context_trigger_tokens'))
    context = '未知' if tokens is None else f'{tokens:,}'
    limit = f'{capacity:,}' if capacity else '未知'
    ratio = f' · {tokens / capacity:.0%}' if tokens is not None and capacity else ''
    threshold = '未知' if trigger is None else f'{trigger:,}'
    info(f"上下文{'估算' if state.get('context_estimated') else ''}: {context}/{limit} tokens{ratio} · "
         f"压缩触发 {threshold} · 累计压缩 {state.get('context_compactions', 0)} 次")
    if state.get('context_saved_tokens', 0):
        before, saved = state['context_before_tokens'], state['context_saved_tokens']
        info(f"上次上下文压缩: {before:,} → {before - saved:,} tokens · 节省 {saved:,}")
    if state.get('plan'):
        info('计划: ' + escape(safe_text(state['plan'])))
    pending = state.get('pending')
    if pending:
        if pending.get('kind') == 'clarification':
            latest = next((m.get('content', '') for m in reversed(state.get('messages', []))
                           if m.get('role') == 'assistant'), '')
            if latest and not (progress and progress.was_shown(latest)):
                from cli.progress import visible_content
                info('模型回复（未验证）: ' + escape(visible_content(latest)))
        question = str(pending.get('question') or '')
        if progress and progress.was_shown(question):
            warn(escape(f"等待回复 [{pending.get('kind')}]: 请回复上方问题"))
        else:
            warn(escape(safe_text(f"等待回复 [{pending.get('kind')}]: {question}")))
        if pending.get('options'):
            info('选项: ' + escape(safe_text(' / '.join(map(str, pending['options'])))))
    elif state.get('answer'):
        answer = state['answer']
        suffix = ' [无证据]'
        if progress and (progress.was_shown(answer) or
                         (answer.endswith(suffix) and progress.was_shown(answer[:-len(suffix)]))):
            ok('任务已结束' + (suffix if answer.endswith(suffix) else ''))
        else:
            ok('模型任务摘要（未验证分析）: ' + escape(safe_text(answer)))


async def run_session(target, settings, batch, is_tty, requested_level, model_override,
                      output_format, output_dir, run_pipeline=None, *, resume_id=None,
                      session_id=None, input_fn=None, llm_factory=None, connection_override=None) -> int:
    from output.session_report import save_session_report
    if output_format not in ('markdown', 'json', 'csv'):
        err('报告格式必须为 markdown/json/csv')
        return 2
    runtime = create_session_runtime(target=target, settings=settings, batch=batch,
        is_tty=is_tty, model_override=model_override, resume_id=resume_id,
        session_id=session_id, llm_factory=llm_factory, connection_override=connection_override)
    gate, identifier = runtime.gate, runtime.session_id
    read = input_fn or input
    exit_code = 0
    def report(state):
        paths = save_session_report(state, gate.current_level(), output_format,
                                    Path(output_dir) if output_dir else None)
        ok(f"报告已生成: {paths['selected']}")
    try:
        async with runtime:
            info(f'会话 ID: {identifier} · 当前 L0，等待任务。')
            info('恢复命令: recon-agent --session --resume ' + shlex.quote(identifier) +
                 ' -t ' + shlex.quote(target) + ' --authorized')
            info('命令: /new 新任务 · /budget cost USD · 状态/status · 报告/report · stop · abort · quit/退出')
            state = await runtime.state()
            show_state(state, gate)
            while True:
                try:
                    text = read('recon> ').strip()
                except KeyboardInterrupt:
                    exit_code = 130
                    break
                except (EOFError, OSError):
                    break
                command = text.lower()
                from cli.session_commands import operator_command, apply_command
                try:
                    operator=operator_command(text)
                except ValueError as exc:
                    warn(str(exc))
                    continue
                if command in ('quit', 'exit', '退出'):
                    break
                if command in ('状态', 'status'):
                    show_state(await runtime.state(), gate)
                elif operator:
                    from utils.logger import console
                    with SessionProgress(console=console(),is_tty=is_tty) as progress:
                        runtime.on_event=progress
                        try: state=await apply_command(runtime,operator)
                        finally: runtime.on_event=None
                    show_state(state,gate,progress)
                elif command in ('报告', '生成报告', 'report'):
                    report(await runtime.state())
                elif command in ('abort', 'stop'):
                    state = await runtime.stop(abort=command == 'abort')
                    show_state(state, gate)
                elif text:
                    try:
                        from utils.logger import console
                        with SessionProgress(console=console(), is_tty=is_tty) as progress:
                            runtime.on_event = progress
                            try:
                                state = (await runtime.resume(text) if (await runtime.state()).get('pending')
                                         else await runtime.submit(text))
                            finally:
                                runtime.on_event = None
                        show_state(state, gate, progress)
                    except (KeyboardInterrupt, asyncio.CancelledError, NodeCancelledError):
                        exit_code = 130
                        warn("会话已中断，未完成工作保留；恢复后需显式继续")
                        break
            state = await runtime.state()
            if state.get('results') or state.get('events') or state.get('executions') or state.get('pending'):
                report(state)
    except (ValueError, RuntimeError) as exc:
        err(f'会话无法打开: {exc}')
        return 2
    return exit_code
