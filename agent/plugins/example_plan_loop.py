"""Small plan-first strategy showing that the graph does not own ReAct policy."""
from __future__ import annotations

from agent.model.base import parse_xml_tool_calls
from agent.plugins.api import PluginManifest
from agent.plugins.loop import Continue, ModelTurn
from agent.plugins.react_loop import ReactLoop


class PlanFirstLoop(ReactLoop):
    manifest = PluginManifest(id='builtin-plan-first', version='1.0', api_version='1.0',
                              capabilities=('loop',))

    def prepare(self, view, state):
        if not state.get('planned'):
            return ModelTurn('First produce a short plan for the task. Do not call tools or finish yet.')
        return ModelTurn()

    def on_response(self, view, response, state):
        if not state.get('planned'):
            if response.tool_calls or parse_xml_tool_calls(response.content):
                raise ValueError('Plan-first loop requires a plan before tool calls')
            return Continue(state={**state, 'planned': True})
        return super().on_response(view, response, state)
