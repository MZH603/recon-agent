"""Decisions nodes for the durable session graph."""
from __future__ import annotations

import json
from uuid import uuid4
from pydantic import ValidationError
from langgraph.types import interrupt
from core.orchestration.controls import CONTROLS, control_specs
from efficiency.budget_guard import BudgetExhausted
from model.base import ModelUnavailable, parse_xml_tool_calls
from tools.base import ToolResult


class DecisionNodes:
    async def _decide(self, state):
        usage = await self.store.usage(self.session_id)
        decisions = max(state['decisions'], usage['decisions'])
        if decisions - state.get('segment_decisions', 0) >= self.max_decisions:
            return self._pause_update('limit', 'Decision limit reached. Continue grants one more bounded segment; budget remains cumulative.', options=['Continue', 'Stop'])
        try:
            self.guard.check()
        except BudgetExhausted as exc:
            return self._pause_update('budget', str(exc), options=['Stop'])
        # Commit the decision reservation before any model call, so crashes cannot reset limits.
        decisions += 1
        await self.store.save_usage(self.session_id, decisions, self.guard.used_tokens, self.guard.used_cost)
        before_tokens, before_cost = self.guard.used_tokens, self.guard.used_cost
        try:
            response = await self.llm.complete(state['messages'], self.registry.specs() + control_specs())
        except (ModelUnavailable, BudgetExhausted) as exc:
            kind = 'budget' if isinstance(exc, BudgetExhausted) else 'model_unavailable'
            return {'decisions': decisions, **self._pause_update(kind, f'{exc}. Choose whether to continue.', options=['Continue', 'Stop'])}
        # Injected providers may not own a BudgetGuard. Avoid double-registering LLMService.
        tokens = response.token_usage.get('input', 0) + response.token_usage.get('output', 0)
        self.guard.used_tokens = max(self.guard.used_tokens, before_tokens + tokens)
        self.guard.used_cost = max(self.guard.used_cost, before_cost + float(response.token_usage.get('cost', 0) or 0))
        await self.store.save_usage(self.session_id, decisions, self.guard.used_tokens, self.guard.used_cost)
        calls = response.tool_calls or parse_xml_tool_calls(response.content)
        native = bool(response.tool_calls)
        message = {'role': 'assistant', 'content': response.content}
        if native:
            message['tool_calls'] = [{'id': c.id, 'type': 'function', 'function':
                {'name': c.name, 'arguments': json.dumps(c.arguments, ensure_ascii=False)}} for c in calls]
        update = {'decisions': decisions, 'used_tokens': self.guard.used_tokens,
                  'used_cost': self.guard.used_cost, 'messages': state['messages'] + [message]}
        if not calls:
            return {**update, **self._pause_update('clarification',
                'The model supplied text without explicit completion. What should happen next?',
                options=['Continue', 'Stop'])}
        return {**update, 'queued_calls': [{**c.model_dump(), 'native': native, 'execution_id': uuid4().hex} for c in calls],
                'route': 'validate', 'pending': None}

    async def _validate(self, state):
        if not state['queued_calls']:
            return {'route': 'decide'}
        call = state['queued_calls'][0]
        if call['name'] in CONTROLS:
            try:
                args = self._arguments(call, CONTROLS[call['name']])
                params = CONTROLS[call['name']].model_validate(args)
            except ValidationError as exc:
                return self._schema_error(state, str(exc))
            if call['name'] == 'ask_user':
                return self._pause_update('ask_user', params.question, options=params.options, action=call['name'])
            result = ToolResult(name=call['name'], success=True, data=params.model_dump()).model_dump()
            update = self._consume(state, result, record=False)
            if call['name'] == 'update_plan':
                return {**update, 'plan': params.plan, 'schema_attempts': 0,
                        'route': 'validate' if update['queued_calls'] else 'decide'}
            known = {e for r in state['results'] if r['success'] for e in r['evidence']}
            evidence_ok = bool(params.evidence) and set(params.evidence) <= known
            clarification_ok = params.clarification_only and not state['results'] and not params.evidence
            if not evidence_ok and not clarification_ok:
                rejected = ToolResult.err(call['name'], 'Completion requires known tool evidence; unsupported findings remain unverified.').model_dump()
                update = self._consume(state, rejected, record=False)
                return {**update, **self._pause_update('evidence', 'Completion has no supporting tool evidence. Clarify the task or continue collecting evidence.', options=['Continue', 'Stop'])}
            closing = self._cancel_queue({**state, **update}, 'Task explicitly completed; queued action cancelled.')
            return {**update, **closing, 'answer': params.answer if evidence_ok else params.answer + ' [无证据]', 'status': 'completed', 'pending': None, 'route': 'end'}
        _, error, kind = self._validate_call(call)
        if error:
            if kind == 'schema':
                return self._schema_error(state, error)
            result = ToolResult.err(call['name'], error).model_dump()
            return {**self._consume(state, result), **self._pause_update(kind, error + ' Choose a safe next step.', options=['Continue', 'Stop'])}
        tool = self.registry.get(call['name'])
        mode = ('l2_unlock' if tool.min_level == 2 and
                (self.gate.current_level() < 2 or not self.gate.verify_signature()) else
                'l2_action' if tool.min_level == 2 else
                'l1' if tool.min_level == 1 and self.gate.current_level() < 1 else 'none')
        return {'route': 'authorize', 'auth_mode': mode, 'auth_process': self.process_id,
                'schema_attempts': 0, 'pending': None}

    async def _pause(self, state):
        pending = state['pending']
        await self.store.record_event(self.session_id, pending)
        value = interrupt(pending)
        if str(value).strip().lower() in ('stop', 'quit', 'exit', '退出', 'abort'):
            if str(value).strip().lower() == 'abort':
                self.gate.abort()
            closing = self._cancel_queue(state, 'Operator stopped the pending task.')
            return {**closing, 'status': 'idle', 'pending': None, 'route': 'end'}
        segment = {}
        if pending['kind'] == 'limit':
            if str(value).strip().lower() not in ('continue', '继续'):
                return {'route': 'pause'}
            usage = await self.store.usage(self.session_id)
            segment = {'segment_decisions': max(state['decisions'], usage['decisions']),
                       'segment_actions': await self.store.action_count(self.session_id)}
        if pending['kind'] == 'ask_user' and state['queued_calls']:
            result = ToolResult(name='ask_user', success=True, data={'answer': value}).model_dump()
            update = self._consume(state, result, record=False)
        elif state['queued_calls'] and str(value).strip().lower() not in ('continue', '继续', 'retry', 'yes'):
            update = self._cancel_queue(state, 'Operator changed the task; pending action cancelled.')
            update['messages'] += [{'role': 'user', 'content': str(value)}]
        elif state['queued_calls']:
            # Native providers require all tool replies directly after their assistant
            # call batch. Defer operator text until the batch has been fully resolved.
            update = {'deferred_user': state.get('deferred_user', []) + [str(value)]}
        else:
            update = {'messages': state['messages'] + [{'role': 'user', 'content': str(value)}]}
        if pending['kind'] == 'schema':
            update['schema_attempts'] = 0
        queue = update.get('queued_calls', state['queued_calls'])
        return {**update, **segment, 'status': 'running', 'pending': None,
                'route': 'validate' if queue else 'decide'}
