"""Execution nodes for the durable session graph."""
from __future__ import annotations

from uuid import uuid4
from time import monotonic
from langgraph.types import interrupt
from hallucination.contradiction import ContradictionDetector
from model.base import NormalizedToolCall
from tools.base import ToolResult


class ExecutionNodes:
    async def _execute(self, state):
        call = state['queued_calls'][0]
        params, error, kind = self._validate_call(call)
        if error:
            return {**self._consume(state, ToolResult.err(call['name'], error).model_dump()),
                    **self._pause_update(kind, error)}
        tool = self.registry.get(call['name'])
        if state.get('auth_process') != self.process_id or self._permit != call['execution_id'] or (
                tool.min_level > self.gate.current_level()) or (tool.min_level == 2 and not self.gate.verify_signature()):
            return {'route': 'validate'}
        arguments = params.model_dump(mode='json')
        previous = await self.store.lookup(self.session_id, call['execution_id'], call['name'], arguments, state.get('task_id', ''),
            reuse_completed=getattr(tool, 'cacheable', True), authorized_retry=bool(call.get('authorized_retry')))
        if previous and previous['status'] == 'completed':
            result = {**previous['result'], 'cached': previous['execution_id'] != call['execution_id']}
            return {'current_result': result, 'route': 'evaluate'}
        if previous and previous['status'] == 'started':
            attempt = 0
            while True:
                question = ('This action may still be executing or its outcome is unknown. Explicitly retry or skip?'
                            if attempt == 0 else 'Please explicitly choose retry or skip.')
                pending = self._pending('uncertain', question,
                                        options=['retry', 'skip'], action=call['name'])
                pending['event_id'] = f"uncertain:{call['execution_id']}:{attempt}"
                await self.store.record_event(self.session_id, pending)
                choice = str(interrupt(pending)).strip().lower()
                if choice in ('retry', 'skip'):
                    break
                # Stay in this node: replay consumes prior invalid replies in order,
                # then the corrected reply resolves the original journal exactly once.
                attempt += 1
            if choice == 'skip':
                result = ToolResult.err(call['name'], 'Uncertain execution skipped by operator.').model_dump()
                return {'current_result': result, 'route': 'evaluate'}
            # A retry is a new action, and L2 always obtains another per-action confirmation.
            # Operator permission applies to this new attempt only. The old outcome
            # remains unknown in the journal, even if the new attempt succeeds.
            retried = {**call, 'execution_id': uuid4().hex, 'authorized_retry': True}
            self._permit = None
            return {'queued_calls': [retried] + state['queued_calls'][1:], 'route': 'validate'}
        actions = await self.store.action_count(self.session_id)
        if actions - state.get('segment_actions', 0) >= self.max_actions:
            return self._pause_update('limit', 'Tool action limit reached. Continue grants one more bounded segment; budget remains cumulative.', options=['Continue', 'Stop'])
        await self.store.start(self.session_id, call['execution_id'], call['name'], arguments, state.get('task_id', ''))
        original_prompt = self.gate._prompt_fn
        consumed = False

        async def verified_step(question):
            nonlocal consumed
            # Registry still runs its complete guard chain. Only this action's already
            # verified L2 prompt can consume the one-shot process-local permit.
            expected = f'<confirm level="2" action="{tool.name}">'
            if consumed or self._permit != call['execution_id'] or not question.startswith(expected):
                return ''
            consumed = True
            return 'yes'

        self.gate._prompt_fn = verified_step
        started = monotonic()
        result = None
        try:
            self._emit('tool_start', name=call['name'], execution_id=call['execution_id'])
            def progress(payload):
                self._emit('tool_late' if payload.get('status')=='late' else 'tool_wait', **payload)
            result = (await self.registry.execute(NormalizedToolCall(id=call['id'], name=call['name'], arguments=arguments),
                execution_id=call['execution_id'], on_progress=progress)).model_dump(mode='json')
        finally:
            self.gate._prompt_fn = original_prompt
            self._permit = None
            if result is None:
                self._emit('tool_cancelled', name=call['name'], execution_id=call['execution_id'], elapsed=monotonic()-started)
        # Completed result is committed before graph checkpointing. A crash after this
        # commit reuses the complete payload instead of repeating the side effect.
        result = self._annotate(call, result)
        from tools.runtime.result_payload import ResultPayloads
        result = ResultPayloads(self.settings).prepare(result, self.target)
        await self.store.complete(self.session_id, call['execution_id'], result)
        self._emit('tool_end', name=call['name'], execution_id=call['execution_id'], success=result['success'],
                   elapsed=monotonic()-started, result=ResultPayloads(self.settings).for_model(result))
        return {'current_result': result, 'actions': actions + 1, 'route': 'evaluate'}

    async def _evaluate(self, state):
        result = state['current_result']
        update = self._consume(state, result)
        update['current_result'] = None
        if result['name'] == 'tool_catalog' and result['success']:
            self.registry.select_tools(result.get('data', {}).get('selected_tools', []))
            update['selected_tool_names'] = self.registry.selected_tool_names
        if not result['success']:
            return {**update, 'route': 'validate' if update['queued_calls'] else 'decide'}
        detector = ContradictionDetector()
        for item in update['results']:
            tech = item.get('data', {}).get('tech') or {}
            if not isinstance(tech, dict):
                continue
            for category, card in tech.items():
                if not isinstance(card, dict):
                    continue
                host = item['data'].get('host', self.target)
                detector.observe(host, category, ' '.join(str(card.get(k, '')) for k in ('name', 'version')).strip(), str(card.get('source', '')))
                for alternative in card.get('alternatives', []):
                    detector.observe(host, category, ' '.join(str(alternative.get(k, '')) for k in ('name', 'version')).strip(), str(alternative.get('source', '')))
        conflicts = detector.conflicts()
        update['conflicts'] = conflicts
        if conflicts and conflicts != state.get('conflicts'):
            return {**update, **self._pause_update('conflict', 'Tool evidence conflicts. Both observations are saved; please choose the next step.', options=['Continue', 'Stop'])}
        return {**update, 'route': 'validate' if update['queued_calls'] else 'decide'}
