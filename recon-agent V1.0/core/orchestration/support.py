"""Support nodes for the durable session graph."""
from __future__ import annotations

import json
from uuid import uuid4
from pydantic import ValidationError
from security.stealth import allowed_target, is_in_scope
from tools.base import ToolResult


class NodeSupport:
    @staticmethod
    def _pending(kind: str, question: str, *, options=None, action=None):
        return {'kind': kind, 'question': question, 'options': options or [], 'action': action,
                'event_id': uuid4().hex}

    def _pause_update(self, kind, question, **kwargs):
        return {'route': 'pause', 'status': 'paused', 'pending': self._pending(kind, question, **kwargs)}

    def _reply(self, call: dict, result: dict) -> dict:
        from tools.runtime.result_payload import ResultPayloads
        from tools.runtime.evidence_store import canonical_json
        content = canonical_json(ResultPayloads(self.settings).for_model(result)).decode('utf-8')
        return ({'role': 'tool', 'tool_call_id': call['id'], 'content': content} if call['native'] else
                {'role': 'user', 'content': '<tool_result>' + content + '</tool_result>',
                 '_context_tool_result': True})

    @staticmethod
    def _arguments(call, model):
        arguments = {k: v for k, v in call['arguments'].items() if not k.startswith('_')}
        if call.get('native', True):
            return arguments
        schema = model.model_json_schema()
        for name, field in schema.get('properties', {}).items():
            if '$ref' in field:
                field = schema.get('$defs', {}).get(field['$ref'].split('/')[-1], field)
            declared = [field] + field.get('anyOf', [])
            if isinstance(arguments.get(name), str) and any(
                    item.get('type') in ('array', 'object') for item in declared):
                try:
                    arguments[name] = json.loads(arguments[name])
                except (ValueError, TypeError):
                    pass  # Preserve the invalid value for the schema error/correction flow.
        return arguments

    def _annotate(self, call, result):
        tool = self.registry.get(call['name'])
        arguments = self._arguments(call, tool.params_model) if tool else call['arguments']
        if tool:
            try:
                arguments = tool.params_model.model_validate(arguments).model_dump(mode='json')
            except ValidationError:
                pass
        return {**result, 'execution_id': call['execution_id'], 'arguments': arguments,
                'target': arguments.get('target', self.target), 'min_level': tool.min_level if tool else 0,
                'cached': result.get('cached', False)}

    def _consume(self, state, result, *, record=True):
        call = state['queued_calls'][0]
        if record:
            result = self._annotate(call, result)
            from tools.runtime.result_payload import ResultPayloads
            result = ResultPayloads(self.settings).prepare(result, self.target)
        queue = state['queued_calls'][1:]
        messages = state['messages'] + [self._reply(call, result)]
        deferred = state.get('deferred_user', [])
        if not queue:
            messages += [{'role': 'user', 'content': text} for text in deferred]
            deferred = []
        return {'queued_calls': queue, 'messages': messages, 'deferred_user': deferred,
                'steps': state.get('steps', 0) + 1,
                'results': state['results'] + ([result] if record else [])}

    def _cancel_queue(self, state, reason):
        messages = list(state['messages'])
        for call in state['queued_calls']:
            messages.append(self._reply(call, ToolResult.err(call['name'], reason).model_dump()))
        messages += [{'role': 'user', 'content': text} for text in state.get('deferred_user', [])]
        return {'messages': messages, 'queued_calls': [], 'deferred_user': []}

    def _validate_call(self, call):
        tool = self.registry.get(call['name'])
        if tool is None:
            return None, f'Unknown tool: {call["name"]}', 'schema'
        clean = self._arguments(call, tool.params_model)
        try:
            params = tool.params_model.model_validate(clean)
        except ValidationError as exc:
            return None, f'Parameter validation failed: {exc.errors()[:3]}', 'schema'
        ok, reason = allowed_target(params.target, self.settings)
        if not ok:
            return None, f'Compliance rejection: {reason}', 'validation'
        if not is_in_scope(params.target, self.target):
            return None, 'Scope rejection: target is outside the operator-authorized scope.', 'validation'
        if not self.guard.allows(tool.min_level):
            return None, '成本预算达到硬上限。用 /budget cost USD 增加成本上限后继续，已用量不清零。', 'budget'
        return params, '', ''

    def _schema_error(self, state, error):
        call = state['queued_calls'][0]
        consumed = self._consume(state, ToolResult.err(call['name'], error).model_dump(),
                                 record=call['name'] not in ('ask_user', 'update_plan', 'finish_task'))
        consumed.update(self._cancel_queue({**state, **consumed}, 'Cancelled pending correction of invalid tool arguments.'))
        attempts = state['schema_attempts'] + 1
        if attempts > 2:
            return {**consumed, 'schema_attempts': attempts,
                    **self._pause_update('schema', 'Two schema correction attempts failed. Please clarify valid parameters.', options=['Continue', 'Stop'])}
        return {**consumed, 'schema_attempts': attempts, 'route': 'decide'}
