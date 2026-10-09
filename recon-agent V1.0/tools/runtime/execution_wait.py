"""A deadline is independent of a tool's willingness to acknowledge cancellation."""
from __future__ import annotations

import asyncio
import inspect
from contextvars import ContextVar
from datetime import datetime, timezone
from time import monotonic
from tools.base import ToolResult
from model.base import observe

partial_output = ContextVar('tool_partial_output', default=None)


class ToolWaiter:
    def __init__(self, settings):
        self.settings = settings
        self.pending = set()
        self.late_results = []

    def timeout_for(self, tool, params):
        value = self.settings.TOOL_TIMEOUT_OVERRIDES.get(tool.name)
        config = getattr(tool, 'config', None)
        if value is None and config is not None:
            value = getattr(config, 'timeout_seconds', None)
        manager = getattr(tool, 'manager', None)
        if value is None and manager is not None:
            config = manager.configs.get(getattr(params, 'server', ''))
            value = getattr(config, 'timeout_seconds', None)
        if value is None and tool.name == 'api_recon':
            value = self.settings.API_RECON_TIMEOUT_SECONDS
        return value or self.settings.TOOL_TIMEOUT_SECONDS

    def _retain(self, task, identifier, callback, target):
        self.pending.add(task)
        def finished(done):
            self.pending.discard(done)
            try:
                result = done.result()
            except (asyncio.CancelledError, Exception):
                return
            record = {'execution_id': identifier, 'status': 'late',
                      'result': result.model_dump(mode='json') if isinstance(result, ToolResult) else str(result)}
            from tools.runtime.result_payload import ResultPayloads
            saved = ResultPayloads(self.settings).prepare({'name':'late_tool_result','success':False,
                'execution_id':identifier,'data':record,'summary':'截止后返回的结果，仅保留诊断，不重新结算'}, target,force=True)
            record['artifacts'] = saved.get('artifacts',[])
            self.late_results.append(record)
            self.late_results[:] = self.late_results[-100:]
            # Full late data is already saved. The observer only receives a
            # bounded diagnostic, so it cannot disconnect a new task's UI.
            payloads = ResultPayloads(self.settings)
            payloads.limit = min(payloads.limit, 16000)
            observe(callback, {**record, 'name':getattr(result,'name','late_tool_result'),
                               'result':payloads.for_model(saved)})
        task.add_done_callback(finished)

    async def run(self, tool, params, identifier, callback=None):
        timeout = self.timeout_for(tool, params)
        started = monotonic()
        captured = {}
        async def invoke():
            partial_output.set(captured)
            if not inspect.iscoroutinefunction(tool.run):
                from platforms.sync_worker import run_sync
                return await run_sync(tool.run, params)
            return await tool.run(params)
        task = asyncio.create_task(invoke())
        def progress():
            observe(callback, {'execution_id': identifier, 'name': tool.name, 'status': 'running',
                              'started_at': started_at, 'elapsed_seconds': monotonic() - started,
                              'timeout_seconds': timeout})
        started_at = datetime.now(timezone.utc).isoformat()
        progress()
        try:
            while not task.done():
                remaining = timeout - (monotonic() - started)
                if remaining <= 0:
                    break
                done, _ = await asyncio.wait({task}, timeout=min(remaining, 1))
                if done:
                    break
                progress()
            if task.done():
                result = task.result()
                if not isinstance(result, ToolResult):
                    result = ToolResult.model_validate(result)
                if not result.success and result.status == 'success':
                    result.status = 'failure'
                result.elapsed_seconds = monotonic() - started
                result.timeout_seconds = timeout
                result.execution_id, result.started_at = identifier, started_at
                # Existing subprocess/custom/MCP adapters report their own timeout.
                if not result.success and (result.exit_code == 124 or result.status == 'timeout' or result.error_code == 'TOOL_TIMEOUT'):
                    result.status, result.error_code = 'timeout', 'TOOL_TIMEOUT'
                    remote = getattr(tool, 'remote_execution', False) or tool.name.startswith('mcp_') or getattr(getattr(tool, 'config', None), 'kind', '') == 'http'
                    result.outcome_unknown = result.outcome_unknown or remote or captured.get('cleanup_confirmed') is False or 'unknown' in result.error.lower()
                return result
            task.cancel()
            done, _ = await asyncio.wait({task}, timeout=self.settings.TOOL_CLEANUP_SECONDS)
            cancelled = bool(done and task.cancelled())
            stopped = cancelled and captured.get('cleanup_confirmed', True)
            if done and not task.cancelled():
                # Consume cancellation races, without accepting a result after the deadline.
                try:
                    task.result()
                except Exception:
                    pass
            if not done:
                self._retain(task, identifier, callback, params.target)
            remote = getattr(tool, 'remote_execution', False) or tool.name.startswith('mcp_') or getattr(getattr(tool, 'config', None), 'kind', '') == 'http'
            return ToolResult(name=tool.name, success=False, status='timeout', exit_code=124,
                              execution_id=identifier, started_at=started_at, confidence=0, degraded=True,
                              error_code='TOOL_TIMEOUT', error=f'工具超过最大等待时间 {timeout:g}s，未取得完整结果',
                              summary=f'等待超时（上限 {timeout:g}s）；取消状态：'+('已取消本地等待' if stopped else '执行是否停止未确认'),
                              elapsed_seconds=monotonic()-started, timeout_seconds=timeout,
                              cancellation_status='cancelled' if stopped else 'pending', outcome_unknown=remote or not stopped,
                              stdout=captured.get('stdout',''),stderr=captured.get('stderr',''),
                              data={'partial_output':bool(captured.get('stdout') or captured.get('stderr'))})
        except asyncio.CancelledError:
            task.cancel()
            done, _ = await asyncio.wait({task}, timeout=self.settings.TOOL_CLEANUP_SECONDS)
            if not done:
                self._retain(task, identifier, callback, params.target)
            else:
                try:
                    task.result()
                except (asyncio.CancelledError, Exception):
                    pass
            if captured.get('stdout') or captured.get('stderr'):
                from tools.runtime.result_payload import ResultPayloads
                saved = ResultPayloads(self.settings).prepare(ToolResult(name=tool.name,
                    success=False, status='cancelled', execution_id=identifier, started_at=started_at,
                    stdout=captured.get('stdout',''),stderr=captured.get('stderr',''),
                    error='操作员取消了本地等待；此产物仅保存已捕获诊断',
                    outcome_unknown=True, elapsed_seconds=monotonic()-started, timeout_seconds=timeout,
                    summary='取消时已捕获的部分输出，仅诊断，不重新交付模型').model_dump(mode='json'),params.target,force=True)
                observe(callback, {'execution_id':identifier,'name':tool.name,'status':'late',
                                   'artifacts':saved.get('artifacts',[]),
                                   'result':{'name':tool.name,'status':'cancelled','summary':saved['summary']}})
            raise

    async def close(self):
        for task in list(self.pending):
            task.cancel()
        if self.pending:
            await asyncio.wait(self.pending, timeout=self.settings.TOOL_CLEANUP_SECONDS)
