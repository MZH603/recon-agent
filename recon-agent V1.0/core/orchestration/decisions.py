"""Decisions nodes for the durable session graph."""
from __future__ import annotations

import json
from uuid import uuid4
from pydantic import ValidationError
from langgraph.types import interrupt
from core.orchestration.controls import CONTROLS, control_specs
from core.orchestration.completion import completion_text, REMINDER
from core.orchestration.model_context import prepare_context
from efficiency.budget_guard import BudgetExhausted
from model.cost import valid_cost
from model.base import ModelUnavailable, parse_xml_tool_calls, StreamUsage, response_events, conservative_tokens
from tools.base import ToolResult


class DecisionNodes:
    async def _decide(self, state):
        usage = await self.store.usage(self.session_id)
        decisions = max(state['decisions'], usage['decisions'])
        task_usage = await self.store.task_usage(self.session_id, state['task_id'])
        unknown_costs = task_usage['cost_unknown_calls']
        estimated_calls = task_usage['usage_estimated_calls']
        if decisions - state.get('segment_decisions', 0) >= self.max_decisions:
            return self._pause_update('limit', 'Decision limit reached. Continue grants one more bounded segment; budget remains cumulative.', options=['Continue', 'Stop'])
        self.registry.select_tools(state.get('selected_tool_names', []))
        tools = self.registry.specs() + control_specs()
        messages, context_update = prepare_context(
            state, self.gate, self.guard, self.settings.CONTEXT_BUDGET,
            getattr(self.settings, 'COMPACT_TRIGGER_RATIO', .70), tools=tools,
            count_tokens=getattr(self.llm, 'count_tokens', None))
        self._emit('context', **{key: value for key, value in context_update.items()
                                if key not in ('context_history', 'context_cursor')})
        try:
            self.guard.check()
        except BudgetExhausted as exc:
            return {**context_update, **self._pause_update('budget', str(exc) + '。用 /budget cost USD 增加费用上限后继续，已用费用不清零。', options=['Stop'])}
        if context_update['context_limited']:
            return {**context_update, **self._pause_update('context_limit',
                'Required instructions, recent turns and tool schemas exceed the context capacity. '
                'Use /new to start a fresh task, reduce the input, or select fewer tools before continuing.',
                options=['Stop'])}
        # Commit the decision reservation before any model call, so crashes cannot reset limits.
        decisions += 1
        await self.store.save_task_usage(self.session_id, state['task_id'], decisions, self.guard.used_tokens, self.guard.used_cost, unknown_costs, estimated_calls)
        before_tokens, before_cost = self.guard.used_tokens, self.guard.used_cost
        partial = StreamUsage()
        response = None
        def forward(delta):
            partial.add(delta)
            self._emit(delta.kind if delta.kind in ('retry', 'fallback') else 'delta', delta=delta)
        try:
            self._emit('model_start')
            if self.on_event is not None and hasattr(self.llm, 'complete_stream'):
                response = await self.llm.complete_stream(messages, tools, forward)
            else:
                response = await self.llm.complete(messages, tools)
                if self.on_event is not None:
                    response_events(response, forward)
        except (ModelUnavailable, BudgetExhausted) as exc:
            kind = 'budget' if isinstance(exc, BudgetExhausted) else 'model_unavailable'
            return {'decisions': decisions, **context_update, **self._pause_update(kind, f'{exc}. Choose whether to continue.', options=['Continue', 'Stop'])}
        finally:
            # Independent journal persistence is required even when the graph node is cancelled.
            if response is not None:
                # Register before end observers: they may propagate cancellation too.
                token_usage = response.token_usage
                known_tokens = {key: isinstance(token_usage.get(key), int) and not isinstance(token_usage.get(key), bool) and token_usage[key] >= 0 for key in ('input', 'output')}
                estimated = not all(known_tokens.values())
                count = getattr(self.llm, 'count_tokens', lambda text: max(1, len(text) // 4))
                input_tokens = token_usage['input'] if known_tokens['input'] else conservative_tokens(json.dumps(messages, ensure_ascii=False) + json.dumps(tools, ensure_ascii=False), count)
                output_tokens = token_usage['output'] if known_tokens['output'] else conservative_tokens(response.content + response.reasoning_content + str(response.tool_calls), count)
                tokens = max(0, input_tokens) + max(0, output_tokens)
                estimated_calls += int(estimated or token_usage.get('estimated', False) or token_usage.get('usage_estimated', False))
                self.guard.used_tokens = max(self.guard.used_tokens, before_tokens + tokens)
                cost = valid_cost(response.token_usage.get('cost'))
                unknown_costs += int(cost is None)
                self.guard.used_cost = max(self.guard.used_cost, before_cost + (cost or 0.0))
            elif partial.started:
                count = getattr(self.llm, 'count_tokens', lambda text: max(1, len(text) // 4))
                consumed = partial.partial(messages, count, tools)
                self.guard.used_tokens = max(self.guard.used_tokens,
                    before_tokens + consumed['input'] + consumed['output'])
                unknown_costs += int(valid_cost(partial.usage.get('cost')) is None)
                estimated_calls += int(consumed['estimated'])
                self.guard.used_cost = max(self.guard.used_cost, before_cost + (valid_cost(partial.usage.get('cost')) or 0.0))
            await self.store.save_task_usage(self.session_id, state['task_id'], decisions, self.guard.used_tokens,
                                        self.guard.used_cost, unknown_costs, estimated_calls)
            self._emit('model_end', success=response is not None)
        calls = response.tool_calls or parse_xml_tool_calls(response.content)
        native = bool(response.tool_calls)
        visible, complete = completion_text(response.content)
        message = {'role': 'assistant', 'content': visible if complete else response.content}
        if response.reasoning_content:
            message['reasoning_content'] = response.reasoning_content
        if native:
            message['tool_calls'] = [{'id': c.id, 'type': 'function', 'function':
                {'name': c.name, 'arguments': json.dumps(c.arguments, ensure_ascii=False)}} for c in calls]
        update = {**context_update, 'decisions': decisions, 'used_tokens': self.guard.used_tokens,
                  'used_cost': self.guard.used_cost, 'cost_unknown_calls': unknown_costs, 'usage_estimated_calls': estimated_calls, 'messages': state['messages'] + [message]}
        if not calls:
            if complete:
                self._emit('completed', answer=visible)
                return {**update, 'answer': visible, 'status': 'completed', 'pending': None, 'route': 'end'}
            return {**update, 'messages': update['messages'] + [{'role': 'system', 'content': REMINDER}],
                    'route': 'decide', 'pending': None}
        return {**update, 'queued_calls': [{**c.model_dump(), 'native': native, 'execution_id': uuid4().hex} for c in calls],
                'route': 'validate', 'pending': None}

    async def _validate(self, state):
        if not state['queued_calls']:
            return {'route': 'decide'}
        if state.get('steps', 0) - state.get('segment_steps', 0) >= self.max_steps:
            return self._pause_update('limit',
                'Queued work limit reached. Continue grants one more bounded segment; budget remains cumulative.',
                options=['Continue', 'Stop'])
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
                self._emit('plan', text=params.plan)
                return {**update, 'plan': params.plan, 'schema_attempts': 0,
                        'route': 'validate' if update['queued_calls'] else 'decide'}
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
        self._emit('pause', pending=pending)
        await self.store.record_event(self.session_id, pending)
        value = interrupt(pending)
        if str(value).strip().lower() in ('stop', 'quit', 'exit', '退出', 'abort'):
            if str(value).strip().lower() == 'abort':
                self.gate.abort()
            closing = self._cancel_queue(state, 'Operator stopped the pending task.')
            return {**closing, 'status': 'stopped', 'pending': None, 'route': 'end'}
        segment = {}
        if pending['kind'] == 'limit':
            if str(value).strip().lower() not in ('continue', '继续'):
                return {'route': 'pause'}
            usage = await self.store.usage(self.session_id)
            segment = {'segment_decisions': max(state['decisions'], usage['decisions']),
                       'segment_actions': await self.store.action_count(self.session_id),
                       'segment_steps': state.get('steps', 0)}
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
