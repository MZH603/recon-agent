"""Public, data-only decision contract for trusted in-process loop plugins."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Protocol

from agent.model.base import LLMResponse, NormalizedToolCall
from agent.plugins.api import PluginManifest


@dataclass(frozen=True)
class LoopView:
    session_id: str
    target: str
    task_goal: str
    messages: tuple[dict[str, Any], ...]
    results: tuple[dict[str, Any], ...]
    plan: str


@dataclass(frozen=True)
class ModelTurn:
    instructions: str = ''


@dataclass(frozen=True)
class ToolBatch:
    calls: tuple[NormalizedToolCall, ...]
    native: bool = False


@dataclass(frozen=True)
class AskUser:
    question: str
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class Complete:
    answer: str


@dataclass(frozen=True)
class Continue:
    state: dict[str, Any] | None = None
    reminder: str = ''


LoopProposal = ModelTurn | ToolBatch | AskUser | Complete | Continue


def serializable_calls(calls) -> tuple[NormalizedToolCall, ...]:
    """Reject tool proposals that cannot survive a JSON checkpoint or journal."""
    normalized = []
    for call in calls:
        item = NormalizedToolCall.model_validate(call)
        json.dumps(item.model_dump(), allow_nan=False)
        normalized.append(item)
    return tuple(normalized)


@dataclass(frozen=True)
class LoopEvent:
    kind: str  # pause | resume
    pending_kind: str
    event_id: str
    value: str | None = None


def serializable_state(value: dict[str, Any] | None) -> dict[str, Any]:
    """Return a detached JSON-compatible private state for checkpointing."""
    if value is None:
        return {}
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError('Loop state must be a JSON object with string keys')
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError('Loop state must be JSON serializable') from exc


class AgentLoop(Protocol):
    manifest: PluginManifest

    def register(self, host, validated_config) -> None: ...
    async def start(self, session_view) -> None: ...
    async def close(self) -> None: ...
    def prepare(self, view: LoopView, state: dict[str, Any]) -> LoopProposal: ...
    def on_response(self, view: LoopView, response: LLMResponse,
                    state: dict[str, Any]) -> LoopProposal: ...
    def on_result(self, view: LoopView, result: dict[str, Any],
                  state: dict[str, Any]) -> dict[str, Any]: ...
    def on_event(self, view: LoopView, event: LoopEvent,
                 state: dict[str, Any]) -> dict[str, Any] | None: ...
