"""Shared idle-first construction for durable session UI adapters."""
from __future__ import annotations

from uuid import uuid4

from core.orchestration import SessionRuntime
from core.prompts import session_prompt
from gate.scan_gate import ScanGate
from model.lazy import LazyLLM


def create_session_runtime(*, target, settings, batch, is_tty, model_override=None,
                           resume_id=None, session_id=None, llm_factory=None,
                           connection_override=None):
    """Construct the runtime without opening its database or creating a model."""
    from platforms.paths import get_config_dir
    from tools.registry import build_default

    identifier = resume_id or session_id or uuid4().hex
    gate = ScanGate(target, batch_mode=batch, is_tty=is_tty, requested_level=0)
    # SessionRuntime binds workspace tools to identifier before any tool runs.
    # Keep the existing three-argument registry factory injection contract.
    registry = build_default(settings, gate, target)
    llm = LazyLLM(settings, model_override, llm_factory,
                  connection_override=connection_override)
    return SessionRuntime(target=target, registry=registry, llm=llm, gate=gate,
        settings=settings, db_path=get_config_dir() / 'agent_state.sqlite',
        session_id=identifier, system_prompt=session_prompt(registry, target, settings),
        require_existing=bool(resume_id))
