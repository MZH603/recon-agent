"""Bounded, data-only contributions to a model request."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol


@dataclass(frozen=True)
class ContextBlock:
    id: str
    source: str
    trust: str
    priority: int
    content: str
    required: bool = False
    estimated_tokens: int | None = None

    def __post_init__(self):
        if (not isinstance(self.id, str) or not self.id or
                not isinstance(self.source, str) or not self.source or
                not isinstance(self.content, str)):
            raise ValueError('Context block requires an ID, source and text content')
        if self.trust not in ('internal', 'external'):
            raise ValueError('Context block trust must be internal or external')
        if type(self.priority) is not int:
            raise ValueError('Context block priority must be an integer')
        if type(self.required) is not bool:
            raise ValueError('Context block required must be a boolean')
        if self.estimated_tokens is not None and (type(self.estimated_tokens) is not int or self.estimated_tokens < 0):
            raise ValueError('Context block estimate must be a nonnegative integer')


@dataclass(frozen=True)
class ContextView:
    state: Mapping
    authorization_level: int
    used_cost: float
    max_cost: float
    budget_state: str
    task_summary: str


class ContextProvider(Protocol):
    required: bool

    def collect(self, view: ContextView) -> list[ContextBlock]: ...


class ContextProviderError(RuntimeError):
    pass


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return copy.deepcopy(value)


def assemble_context(state, gate, guard, capacity, *, providers=(), tools=None,
                     trigger_ratio=.7, count_tokens=None, compact=True,
                     compaction_policy=None, extra_messages=()):
    """Collect immutable data, assemble in host-owned roles, then count the full request."""
    from agent.core.orchestration.model_context import prepare_context, _task_context

    dynamic = _task_context(state, gate, guard)
    view = ContextView(state=_freeze(state), authorization_level=gate.current_level(),
                       used_cost=guard.used_cost, max_cost=guard.max_cost,
                       budget_state=guard.state().value, task_summary=dynamic['content'])
    blocks = []
    errors = []
    seen = set()
    for provider in providers:
        ident = provider.manifest.id
        try:
            contribution = provider.collect(view)
            if not isinstance(contribution, (list, tuple)):
                raise TypeError('collect() must return a list of ContextBlock')
            provider_blocks = []
            provider_ids = set()
            for block in contribution:
                if not isinstance(block, ContextBlock):
                    raise TypeError('collect() must return ContextBlock values')
                if block.source != ident:
                    raise ValueError(f'Block source mismatch: {block.source}')
                key = (block.source, block.id)
                if key in seen or key in provider_ids:
                    continue
                provider_ids.add(key)
                provider_blocks.append(block)
            seen.update(provider_ids)
            blocks.extend(provider_blocks)
        except Exception as exc:
            if getattr(provider, 'required', False):
                raise ContextProviderError(f'{ident}: {exc}') from exc
            errors.append({'provider': ident, 'error': str(exc)})
    blocks.sort(key=lambda block: (-block.priority, block.source, block.id))

    # Only the host's task/gate summary occupies a system role. Even a plugin
    # claiming internal trust is serialized as labelled data in a user message.
    builtin = next((block for block in blocks if block.source == 'builtin-context'), None)
    if builtin is not None:
        dynamic = {'role': 'system', 'content': builtin.content}
        blocks.remove(builtin)
    def render(current):
        return [{'role': 'user', 'content': f'[{block.source}:{block.id}] '
                 f'Context data (trust={block.trust}):\n{block.content}'} for block in current]
    active = list(blocks)
    # Optional data has lower retention priority than durable conversation.
    # Check the full request before allowing the history compactor to run.
    while True:
        _, preview = prepare_context(state, gate, guard, capacity, trigger_ratio,
            tools=tools, count_tokens=count_tokens, compact=False,
            dynamic_message=dynamic, blocks=render(active) + list(extra_messages))
        optional = [block for block in active if not block.required]
        if preview['context_tokens'] < preview['context_trigger_tokens'] or not optional:
            break
        active.remove(min(optional, key=lambda block: (block.priority, block.source, block.id)))
    try:
        messages, metrics = prepare_context(state, gate, guard, capacity, trigger_ratio,
            tools=tools, count_tokens=count_tokens, compact=compact,
            dynamic_message=dynamic, blocks=render(active) + list(extra_messages),
            compaction_policy=compaction_policy)
    except Exception as exc:
        if compaction_policy is not None:
            raise ContextProviderError(f'compaction policy: {exc}') from exc
        raise
    return messages, metrics, errors
