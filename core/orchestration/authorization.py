"""Authorization nodes for the durable session graph."""
from __future__ import annotations

import json
from langgraph.types import interrupt
from tools.base import ToolResult
from core.orchestration.store import signature


class AuthorizationNodes:
    async def _authorize(self, state):
        call = state['queued_calls'][0]
        _, error, kind = self._validate_call(call)
        if error:
            return {**self._consume(state, ToolResult.err(call['name'], error).model_dump()),
                    **self._pause_update(kind, error)}
        tool = self.registry.get(call['name'])
        mode = state['auth_mode']
        original_prompt = self.gate._prompt_fn

        async def prompt(question):
            pending = self._pending('authorization', question, action=call['name'])
            pending['event_id'] = signature('authorization', {'process': self.process_id,
                                           'execution': call['execution_id'], 'question': question})
            await self.store.record_event(self.session_id, pending)
            return str(interrupt(pending))

        self.gate._prompt_fn = prompt
        try:
            if tool.min_level == 2 and (self.gate.batch_mode or not self.gate.is_tty):
                return self._pause_update('authorization_blocked', 'L2 requires an interactive TTY and cannot run in batch mode.', options=['Stop'])
            if mode == 'l1' and not await self.gate.request_level_1(tool.description):
                return self._pause_update('authorization_denied', 'L1 authorization was declined. Choose a next step.', options=['Continue', 'Stop'])
            if mode == 'l2_unlock':
                # Mode is fixed by validate, keeping interrupt replay order stable.
                for step in (1, 2, 3):
                    granted, _ = await self.gate.request_level_2_step(step, state['plan'] or tool.description)
                    if not granted:
                        return self._pause_update('authorization_denied', 'An exact L2 confirmation was declined. Choose a next step.', options=['Continue', 'Stop'])
            if tool.min_level == 2:
                if not self.gate.verify_signature() or self.gate.current_level() < 2:
                    return {'route': 'validate'}
                if not await self.gate.confirm_step(tool.name,
                        f'{tool.name} {json.dumps(call["arguments"], ensure_ascii=False)}', tool.risk_level):
                    return self._pause_update('authorization_denied', 'The L2 action was declined. Choose a next step.', options=['Continue', 'Stop'])
            self._permit = call['execution_id']
            return {'route': 'execute', 'pending': None}
        finally:
            self.gate._prompt_fn = original_prompt
