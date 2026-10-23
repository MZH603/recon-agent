"""Serializable state persisted by the session graph; no authorization grants."""
from typing import Any, TypedDict
from uuid import uuid4


class SessionState(TypedDict, total=False):
    selected_tool_names: list[str]
    task_id: str
    segment_decisions: int
    segment_actions: int
    steps: int
    segment_steps: int
    session_id: str
    target: str
    messages: list[dict[str, Any]]
    context_history: list[dict[str, Any]]
    context_cursor: int
    context_tokens: int
    context_capacity: int
    context_trigger_tokens: int
    context_before_tokens: int
    context_saved_tokens: int
    context_compactions: int
    context_compressed: bool
    context_limited: bool
    context_estimated: bool
    deferred_user: list[str]
    plan: str
    queued_calls: list[dict[str, Any]]
    results: list[dict[str, Any]]
    answer: str
    status: str
    pending: dict[str, Any] | None
    decisions: int
    actions: int
    max_tokens: int
    max_cost: float
    session_used_tokens: int
    session_used_cost: float
    usage_estimated_calls: int
    task_goal: str
    used_tokens: int
    used_cost: float
    cost_unknown_calls: int
    schema_attempts: int
    route: str
    auth_mode: str
    auth_process: str
    current_result: dict[str, Any] | None
    conflicts: list[dict[str, Any]]
    events: list[dict[str, Any]]
    executions: list[dict[str, Any]]


def initial_state(session_id: str, target: str, system_prompt: str) -> SessionState:
    return SessionState(selected_tool_names=[], task_id=uuid4().hex, segment_decisions=0, segment_actions=0,
                        steps=0, segment_steps=0,
                        session_id=session_id, target=target,
                        messages=[{'role': 'system', 'content': system_prompt}] if system_prompt else [],
                        context_history=[], context_cursor=0, context_tokens=0,
                        context_capacity=0, context_trigger_tokens=0, context_before_tokens=0,
                        context_saved_tokens=0, context_compactions=0, context_compressed=False,
                        context_limited=False, context_estimated=True,
                        plan='', deferred_user=[], queued_calls=[], results=[], answer='', status='idle', pending=None,
                        decisions=0, actions=0, used_tokens=0, used_cost=0.0, cost_unknown_calls=0, usage_estimated_calls=0, task_goal='',
                        schema_attempts=0, conflicts=[], events=[], executions=[], route='end')
