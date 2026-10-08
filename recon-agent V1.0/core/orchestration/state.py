"""Serializable state persisted by the session graph; no authorization grants."""
from typing import Any, TypedDict
from uuid import uuid4


class SessionState(TypedDict, total=False):
    task_id: str
    segment_decisions: int
    segment_actions: int
    steps: int
    segment_steps: int
    session_id: str
    target: str
    messages: list[dict[str, Any]]
    deferred_user: list[str]
    plan: str
    queued_calls: list[dict[str, Any]]
    results: list[dict[str, Any]]
    answer: str
    status: str
    pending: dict[str, Any] | None
    decisions: int
    actions: int
    used_tokens: int
    used_cost: float
    schema_attempts: int
    route: str
    auth_mode: str
    auth_process: str
    current_result: dict[str, Any] | None
    conflicts: list[dict[str, Any]]
    events: list[dict[str, Any]]
    executions: list[dict[str, Any]]


def initial_state(session_id: str, target: str, system_prompt: str) -> SessionState:
    return SessionState(task_id=uuid4().hex, segment_decisions=0, segment_actions=0,
                        steps=0, segment_steps=0,
                        session_id=session_id, target=target,
                        messages=[{'role': 'system', 'content': system_prompt}] if system_prompt else [],
                        plan='', deferred_user=[], queued_calls=[], results=[], answer='', status='idle', pending=None,
                        decisions=0, actions=0, used_tokens=0, used_cost=0.0,
                        schema_attempts=0, conflicts=[], events=[], executions=[], route='end')
