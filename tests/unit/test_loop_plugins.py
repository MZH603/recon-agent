"""Loop strategies propose decisions but never receive the tool executor."""
import json

import pytest

from agent.model.base import LLMResponse, NormalizedToolCall
from agent.plugins.api import PluginManifest
from agent.plugins.loop import LoopView, ModelTurn, ToolBatch, Complete, Continue, serializable_state
from agent.plugins.react_loop import ReactLoop
from agent.plugins.example_plan_loop import PlanFirstLoop
from agent.plugins.host import PluginHost
from agent.gate.scan_gate import ScanGate
from agent.tools.registry import ToolRegistry
from agent.utils.config import Settings


def view(**values):
    return LoopView(session_id='s', target='example.com', task_goal='Inspect',
                    messages=(), results=(), plan='', **values)


def test_react_proposes_native_tools_and_completion():
    loop = ReactLoop()
    assert isinstance(loop.prepare(view(), {}), ModelTurn)
    response = LLMResponse(content='', tool_calls=[NormalizedToolCall(
        id='call-1', name='dns_query', arguments={'target': 'example.com'})])
    proposal = loop.on_response(view(), response, {})
    assert isinstance(proposal, ToolBatch)
    assert proposal.native is True
    assert proposal.calls[0].name == 'dns_query'
    complete = loop.on_response(view(), LLMResponse(content='Finished\n<task_complete/>'), {})
    assert isinstance(complete, Complete)
    assert complete.answer == 'Finished'


def test_plan_first_changes_first_model_turn_then_uses_react():
    loop = PlanFirstLoop()
    first = loop.prepare(view(), {})
    assert isinstance(first, ModelTurn)
    assert 'plan' in first.instructions.lower()
    response = loop.on_response(view(), LLMResponse(content='Plan ready'), {})
    assert isinstance(response, Continue)
    assert response.state == {'planned': True}
    second = loop.prepare(view(), response.state)
    assert isinstance(second, ModelTurn)
    assert second.instructions == ''


def test_loop_state_is_json_serializable_and_rejects_foreign_objects():
    assert serializable_state({'steps': [1, 'x']}) == {'steps': [1, 'x']}
    with pytest.raises(ValueError, match='JSON'):
        serializable_state({'bad': object()})
    json.dumps(serializable_state({'ok': True}))


def test_host_rejects_multiple_loop_plugins():
    settings = Settings()
    gate = ScanGate('example.com', batch_mode=True, is_tty=False)
    host = PluginHost(ToolRegistry(settings, gate, 'example.com'))
    with pytest.raises(ValueError, match='loop'):
        host.load([(ReactLoop(), {}), (PlanFirstLoop(), {})])


def test_host_requires_pause_resume_event_hook_for_loop_plugin():
    class MissingEvents(ReactLoop):
        manifest = PluginManifest(id='missing-events', version='1.0', api_version='1.0',
                                  capabilities=('loop',))
        on_event = None
    settings = Settings()
    gate = ScanGate('example.com', batch_mode=True, is_tty=False)
    host = PluginHost(ToolRegistry(settings, gate, 'example.com'))
    with pytest.raises(ValueError, match='on_event'):
        host.load([(MissingEvents(), {})])
