"""Durable async LangGraph runtime lifecycle and operator API."""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from pathlib import Path
from uuid import uuid4

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from core.orchestration.authorization import AuthorizationNodes
from core.orchestration.decisions import DecisionNodes
from core.orchestration.execution import ExecutionNodes
from core.orchestration.support import NodeSupport
from core.orchestration.state import SessionState, initial_state
from core.orchestration.store import SessionStore
from efficiency.budget_guard import BudgetGuard
from gate.scan_gate import ScanGate
from tools.registry import ToolRegistry
from utils.config import Settings


class SessionRuntime(DecisionNodes, AuthorizationNodes, ExecutionNodes, NodeSupport):
    """Use as an async context manager; startup is idle and makes no external calls.

    submit(text) starts an operator task; resume(value) replies to an interrupt.
    state() is a JSON-compatible snapshot, including pending{kind,question,options,action}.
    Only the injected ScanGate owns authorization; checkpoint state contains no grants."""

    def __init__(self, *, target: str, registry: ToolRegistry, llm, gate: ScanGate,
                 settings: Settings, db_path: str | Path, session_id: str,
                 system_prompt: str = '', max_decisions: int = 15, max_actions: int = 15,
                 require_existing: bool = False):
        if max_decisions < 1 or max_actions < 1:
            raise ValueError('Task decision and action limits must be positive')
        if registry.main_target != target or gate.target != target or registry._gate is not gate:
            raise ValueError('Registry, gate and runtime must use the same target and gate')
        self.target, self.registry, self.llm, self.gate = target, registry, llm, gate
        self.settings, self.db_path, self.session_id = settings, Path(db_path), session_id
        self.system_prompt = system_prompt
        self.require_existing = require_existing
        self.max_decisions, self.max_actions = max_decisions, max_actions
        self.process_id = uuid4().hex
        self.config = {'configurable': {'thread_id': session_id},
                       'recursion_limit': max_decisions * 10 + max_actions * 10 + 100}
        self.store = SessionStore(self.db_path)
        self.graph = None
        self._stack = AsyncExitStack()
        self._lock = asyncio.Lock()
        self._permit = None  # one action, in this process only

    async def __aenter__(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            await self.store.open()
            self._stack.push_async_callback(self.store.close)
            saver = await self._stack.enter_async_context(AsyncSqliteSaver.from_conn_string(str(self.db_path)))
            await saver.setup()
            builder = StateGraph(SessionState)
            for name in ('decide', 'validate', 'authorize', 'execute', 'evaluate', 'pause'):
                builder.add_node(name, getattr(self, '_' + name))
                builder.add_conditional_edges(name, lambda state: state['route'],
                    {node: node for node in ('decide', 'validate', 'authorize', 'execute', 'evaluate', 'pause')} | {'end': END})
            builder.add_edge(START, 'decide')
            self.graph = builder.compile(checkpointer=saver)
            snapshot = await self.graph.aget_state(self.config)
            if snapshot.values:
                if snapshot.values['target'] != self.target:
                    raise ValueError('Stored session belongs to another target')
            else:
                if self.require_existing:
                    raise ValueError(f'Session {self.session_id} does not exist')
                await self.graph.aupdate_state(self.config,
                    initial_state(self.session_id, self.target, self.system_prompt), as_node='decide')
            await self._restore_budget()
            return self
        except BaseException:
            await self._stack.aclose()
            raise

    async def __aexit__(self, *exc):
        await self._stack.aclose()

    def _require_open(self):
        if self.graph is None or self.store.connection is None:
            raise RuntimeError('SessionRuntime must be used inside an async context')

    async def _restore_budget(self):
        snapshot = await self.graph.aget_state(self.config)
        usage = await self.store.usage(self.session_id)
        values = snapshot.values
        used_tokens = max(values.get('used_tokens', 0), usage['used_tokens'])
        used_cost = max(values.get('used_cost', 0.0), usage['used_cost'])
        self.guard = getattr(self.llm, 'guard', None) or BudgetGuard()
        self.guard.max_tokens, self.guard.max_cost = self.settings.MAX_TOKENS_PER_TASK, self.settings.MAX_COST_PER_TASK
        self.guard.used_tokens, self.guard.used_cost = used_tokens, used_cost

    async def state(self) -> dict:
        self._require_open()
        snapshot = await self.graph.aget_state(self.config)
        values = dict(snapshot.values)
        usage = await self.store.usage(self.session_id)
        for key, value in usage.items():
            values[key] = max(values.get(key, 0), value)
        values['events'] = await self.store.events(self.session_id)
        values['executions'] = await self.store.executions(self.session_id)
        values['actions'] = max(values.get('actions', 0), await self.store.action_count(self.session_id))
        has_interrupt = False
        for task in snapshot.tasks:
            if task.interrupts:
                has_interrupt = True
                values['status'] = 'paused'
                values['pending'] = task.interrupts[0].value
                break
        if snapshot.next and not has_interrupt:
            values['status'] = 'paused'
            values['pending'] = self._pending('recovery',
                'A checkpoint has unfinished work. Continue recovery or stop?', options=['Continue', 'Stop'])
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
                      'task_id': current.get('task_id') if not current['decisions'] else uuid4().hex,
                      'segment_decisions': current['decisions'], 'segment_actions': current['actions'],
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
        """Persist an idle session without executing pending graph work."""
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
             'status': 'idle', 'pending': None, 'route': 'end'}, as_node='decide')
        return await self.state()
