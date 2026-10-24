"""Durable async LangGraph runtime lifecycle and operator API."""
from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack
from pathlib import Path
from uuid import uuid4

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from agent.core.orchestration.authorization import AuthorizationNodes
from agent.core.orchestration.decisions import DecisionNodes
from agent.core.orchestration.execution import ExecutionNodes
from agent.core.orchestration.support import NodeSupport
from agent.core.orchestration.state import SessionState, initial_state
from agent.core.orchestration.store import SessionStore
from agent.core.orchestration.ownership import SessionOwnership
from agent.efficiency.budget_guard import BudgetGuard
from agent.gate.scan_gate import ScanGate
from agent.tools.registry import ToolRegistry
from agent.utils.config import Settings
from agent.model.base import observe
from agent.plugins.loop import LoopEvent, LoopView, serializable_state
from agent.plugins.react_loop import ReactLoop


class SessionRuntime(DecisionNodes, AuthorizationNodes, ExecutionNodes, NodeSupport):
    """Use as an async context manager; startup is idle and makes no external calls.

    submit(text) starts an operator task; resume(value) replies to an interrupt.
    state() is a JSON-compatible snapshot, including pending{kind,question,options,action}.
    Only the injected ScanGate owns authorization; checkpoint state contains no grants."""

    def __init__(self, *, target: str, registry: ToolRegistry, llm, gate: ScanGate,
                 settings: Settings, db_path: str | Path, session_id: str,
                 system_prompt: str = '', max_decisions: int = 15, max_actions: int = 15,
                 require_existing: bool = False, max_steps: int | None = None, on_event=None):
        max_steps = max_decisions + max_actions if max_steps is None else max_steps
        if max_decisions < 1 or max_actions < 1 or max_steps < 1:
            raise ValueError('Task decision, action and step limits must be positive')
        if registry.main_target != target or gate.target != target or registry._gate is not gate:
            raise ValueError('Registry, gate and runtime must use the same target and gate')
        self.target, self.registry, self.llm, self.gate = target, registry, llm, gate
        self.settings, self.db_path, self.session_id = settings, Path(db_path).resolve(), session_id
        registry.bind_session(session_id)
        self.system_prompt = system_prompt
        self.on_event = on_event
        self.require_existing = require_existing
        self.max_decisions, self.max_actions = max_decisions, max_actions
        self.max_steps = max_steps
        self._ownership = SessionOwnership(self.db_path, session_id)
        self._entered = False
        self.process_id = uuid4().hex
        self.config = {'configurable': {'thread_id': session_id},
                       'recursion_limit': max_decisions * 10 + max_actions * 10 + max_steps * 5 + 100}
        self.store = SessionStore(self.db_path)
        self.graph = None
        self._stack = AsyncExitStack()
        self._lock = asyncio.Lock()
        self._permit = None  # one action, in this process only
        host = registry.plugin_host
        self.loop = host.loop_provider if host is not None and host.loop_provider is not None else ReactLoop()
        if self.loop.manifest.id != settings.agent_loop:
            raise ValueError(f'Configured agent loop is not available: {settings.agent_loop}')

    def _loop_view(self, state):
        # A detached snapshot gives plugins data, never the registry, gate, model or store.
        return LoopView(session_id=self.session_id, target=self.target,
            task_goal=state.get('task_goal', ''),
            messages=tuple(json.loads(json.dumps(state.get('messages', [])))),
            results=tuple(json.loads(json.dumps(state.get('results', [])))),
            plan=state.get('plan', ''))

    def _loop_private(self, state):
        return serializable_state(state.get('loop_state', {}).get(self.loop.manifest.id))

    def _loop_update(self, state, private):
        return {'loop_state': {**state.get('loop_state', {}),
                               self.loop.manifest.id: serializable_state(private)}}

    def _loop_result_update(self, state, update, result):
        private = self.loop.on_result(self._loop_view({**state, **update}),
            json.loads(json.dumps(result)), self._loop_private(state))
        return self._loop_update(state, private)

    def _loop_event_update(self, state, kind, pending, value=None):
        event = LoopEvent(kind=kind, pending_kind=pending['kind'],
            event_id=pending['event_id'], value=None if value is None else str(value))
        private = self.loop.on_event(self._loop_view(state), event, self._loop_private(state))
        return self._loop_update(state, private) if private is not None else {}

    async def _run_node(self, name, state):
        update = await getattr(self, '_' + name)(state)
        # A node's returned update is checkpointed before the pause interrupt.
        # Emitting here avoids replaying the pause hook when LangGraph resumes it.
        if name != 'pause' and update.get('route') == 'pause':
            pending = update.get('pending')
            if pending and pending.get('kind') != 'agent_loop':
                try:
                    current = {**state, **update}
                    update = {**update, **self._loop_event_update(current, 'pause', pending)}
                except Exception as exc:
                    update = {**update, **self._loop_error(exc)}
        return update

    def _emit(self, kind, **payload):
        observe(self.on_event, {'kind': kind, **payload})

    async def __aenter__(self):
        if self._entered:
            raise ValueError(f'Session {self.session_id} runtime is already active')
        self._entered = True
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._ownership.acquire()
            self._stack.callback(self._ownership.release)
            self._stack.push_async_callback(self.registry.aclose)
            await self.store.open()
            self._stack.push_async_callback(self.store.close)
            saver = await self._stack.enter_async_context(AsyncSqliteSaver.from_conn_string(str(self.db_path)))
            await saver.setup()
            builder = StateGraph(SessionState)
            for name in ('decide', 'validate', 'authorize', 'execute', 'evaluate', 'pause'):
                async def run_node(state, node_name=name):
                    return await self._run_node(node_name, state)
                builder.add_node(name, run_node)
                builder.add_conditional_edges(name, lambda state: state['route'],
                    {node: node for node in ('decide', 'validate', 'authorize', 'execute', 'evaluate', 'pause')} | {'end': END})
            builder.add_edge(START, 'decide')
            self.graph = builder.compile(checkpointer=saver)
            snapshot = await self.graph.aget_state(self.config)
            if snapshot.values:
                if snapshot.values['target'] != self.target:
                    raise ValueError('Stored session belongs to another target')
                stored_loop = snapshot.values.get('loop_id', 'builtin-react')
                if stored_loop != self.loop.manifest.id:
                    raise ValueError(f'Stored agent loop {stored_loop} differs from configured {self.loop.manifest.id}')
            else:
                if self.require_existing:
                    raise ValueError(f'Session {self.session_id} does not exist')
                initial = initial_state(self.session_id, self.target, self.system_prompt)
                initial['loop_id'] = self.loop.manifest.id
                await self.graph.aupdate_state(self.config, initial, as_node='decide')
            self.registry.select_tools(snapshot.values.get('selected_tool_names', []))
            await self._restore_budget()
            if self.registry.plugin_host is not None:
                await self.registry.plugin_host.start(self)
            return self
        except BaseException:
            try:
                await self._stack.aclose()
            finally:
                self._entered = False
            raise

    async def __aexit__(self, *exc):
        try:
            await self._stack.aclose()
        finally:
            self._entered = False

    def _require_open(self):
        if self.graph is None or self.store.connection is None:
            raise RuntimeError('SessionRuntime must be used inside an async context')

    def _assemble_context(self, values, tools, *, compact, extra_messages=()):
        from agent.plugins.context import assemble_context
        host = self.registry.plugin_host
        return assemble_context(values, self.gate, self.guard,
            self.settings.CONTEXT_BUDGET,
            providers=host.context_providers if host is not None else (),
            trigger_ratio=self.settings.COMPACT_TRIGGER_RATIO,
            tools=tools, count_tokens=getattr(self.llm, 'count_tokens', None),
            compact=compact,
            compaction_policy=host.compaction_policy if host is not None else None,
            extra_messages=extra_messages)

    async def _restore_budget(self):
        snapshot = await self.graph.aget_state(self.config)
        values = snapshot.values
        task_id = values.get('task_id') or uuid4().hex
        usage = await self.store.ensure_task(self.session_id, task_id, values,
            0, self.settings.MAX_COST_PER_TASK)
        self.guard = getattr(self.llm, 'guard', None) or BudgetGuard()
        self.guard.max_tokens, self.guard.max_cost = 0, usage['max_cost']
        self.guard.used_tokens, self.guard.used_cost = usage['used_tokens'], usage['used_cost']
        if values.get('task_id') != task_id:
            await self.graph.aupdate_state(self.config, {'task_id': task_id}, as_node='decide')

    async def state(self) -> dict:
        self._require_open()
        snapshot = await self.graph.aget_state(self.config)
        values = dict(snapshot.values)
        usage = await self.store.usage(self.session_id)
        task_usage = await self.store.task_usage(self.session_id, values['task_id'])
        values.update(task_usage or {})
        values['max_tokens'] = 0
        values['decisions'] = max(values.get('decisions', 0), usage['decisions'])
        values['session_used_tokens'] = usage['used_tokens']
        values['session_used_cost'] = usage['used_cost']
        values['steps'] = values.get('steps', 0)
        values['events'] = await self.store.events(self.session_id)
        values['executions'] = await self.store.executions(self.session_id)
        values['actions'] = max(values.get('actions', 0), await self.store.action_count(self.session_id))
        has_interrupt = False
        for task in snapshot.tasks:
            if task.interrupts:
                has_interrupt = True
                values['status'] = 'paused'
                values['pending'] = {**task.interrupts[0].value,
                                     'interrupt_id': task.interrupts[0].id}
                break
        if snapshot.next and not has_interrupt:
            values['status'] = 'paused'
            values['pending'] = self._pending('recovery',
                'A checkpoint has unfinished work. Continue recovery or stop?', options=['Continue', 'Stop'])
        from agent.core.orchestration.controls import control_specs
        from agent.plugins.context import ContextProviderError
        try:
            _, context, _ = self._assemble_context(values,
                self.registry.specs() + control_specs(), compact=False)
        except ContextProviderError as exc:
            # Preview remains available so an operator can inspect/stop a
            # paused session even when a required source is offline.
            from agent.core.orchestration.model_context import prepare_context
            _, context = prepare_context(values, self.gate, self.guard,
                self.settings.CONTEXT_BUDGET, self.settings.COMPACT_TRIGGER_RATIO,
                tools=self.registry.specs() + control_specs(),
                count_tokens=getattr(self.llm, 'count_tokens', None), compact=False)
            values['context_error'] = str(exc)
        values.update({key: context[key] for key in (
            'context_tokens', 'context_capacity', 'context_trigger_tokens', 'context_estimated')})
        return values

    async def submit(self, text: str) -> dict:
        self._require_open()
        if not text.strip():
            return await self.state()
        async with self._lock:
            current = await self.state()
            snapshot = await self.graph.aget_state(self.config)
            if snapshot.next:
                raise ValueError('Session is paused; reply with resume(value)')
            await self._restore_budget()
            values = {**current, 'messages': current['messages'] + [{'role': 'user', 'content': text}],
                      'status': 'running', 'pending': None, 'answer': '', 'route': 'decide',
                      'task_id': current['task_id'],
                      'task_goal': current.get('task_goal') or text,
                      'segment_decisions': current['decisions'], 'segment_actions': current['actions'],
                      'segment_steps': current['steps'],
                      'schema_attempts': 0}
            await self.graph.ainvoke(values, self.config)
            return await self.state()

    async def resume(self, value) -> dict:
        self._require_open()
        async with self._lock:
            snapshot = await self.graph.aget_state(self.config)
            if not snapshot.next:
                raise ValueError('Session has no pending interrupt')
            await self._restore_budget()
            state = dict(snapshot.values)
            if str(value).strip().lower() in ('stop', 'quit', 'exit', '退出', 'abort'):
                return await self._stop_locked(str(value).strip().lower() == 'abort')
            # Recreate pending scan tasks in a new process, discarding LangGraph's replayed
            # interrupt responses. Even old execute checkpoints must revalidate/re-authorize.
            if state.get('queued_calls') and state.get('auth_process') != self.process_id and (
                    any(node in snapshot.next for node in ('authorize', 'execute'))):
                self._permit = None
                await self.graph.aupdate_state(self.config,
                    {'route': 'validate', 'pending': None, 'auth_process': ''}, as_node='decide')
                await self.graph.ainvoke(None, self.config)
            else:
                await self.graph.ainvoke(Command(resume=value), self.config)
            return await self.state()

    async def stop(self, abort: bool = False) -> dict:
        """Persist a stopped session without executing pending graph work."""
        self._require_open()
        async with self._lock:
            return await self._stop_locked(abort)

    async def _stop_locked(self, abort: bool) -> dict:
        if abort:
            self.gate.abort()
        self._permit = None
        snapshot = await self.graph.aget_state(self.config)
        await self.graph.aupdate_state(self.config,
            {**self._cancel_queue(dict(snapshot.values), 'Operator stopped the pending task.'),
             'status': 'stopped', 'pending': None, 'route': 'end'}, as_node='decide')
        return await self.state()


    async def add_budget(self, tokens: int = 0, cost: float = 0) -> dict:
        """Raise the current task cost limit without running a model or resetting usage."""
        import math
        self._require_open()
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens != 0:
            raise ValueError('Token budget additions are no longer supported; use cost=USD for a cost budget addition')
        if isinstance(cost, bool) or not isinstance(cost, (int, float)) or not math.isfinite(cost) or cost < 0:
            raise ValueError('Cost budget additions must be finite nonnegative amounts')
        async with self._lock:
            current = await self.state()
            await self.store.add_budget(self.session_id, current['task_id'], 0, cost)
            await self._restore_budget()
            return await self.state()

    async def new_task(self) -> dict:
        """Archive the current task and open an idle task; callers cancel active runs first."""
        self._require_open()
        async with self._lock:
            previous = await self.state()
            await self._stop_locked(False)
            current = await self.state()
            if previous.get('status') == 'completed':
                current['status'] = 'completed'
            await self.store.archive_task(self.session_id, current['task_id'], current)
            values = initial_state(self.session_id, self.target, self.system_prompt)
            values['loop_id'] = self.loop.manifest.id
            values.update(selected_tool_names=current.get('selected_tool_names', []),
                decisions=current['decisions'], actions=current['actions'], steps=current['steps'],
                segment_decisions=current['decisions'], segment_actions=current['actions'],
                segment_steps=current['steps'])
            await self.store.ensure_task(self.session_id, values['task_id'], values,
                0, self.settings.MAX_COST_PER_TASK, fresh=True)
            await self.graph.aupdate_state(self.config, values, as_node='decide')
            self._permit = None
            await self._restore_budget()
            self._emit('new_task', task_id=values['task_id'])
            return await self.state()
