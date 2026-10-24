"""Existing model/tool/completion decisions as the default loop plugin."""
from __future__ import annotations

from agent.model.base import parse_xml_tool_calls
from agent.plugins.api import PluginManifest
from agent.plugins.loop import Complete, Continue, ModelTurn, ToolBatch


class ReactLoop:
    manifest = PluginManifest(id='builtin-react', version='1.0', api_version='1.0',
                              capabilities=('loop',))

    def register(self, host, validated_config): pass
    async def start(self, session_view): pass
    async def close(self): pass

    def prepare(self, view, state):
        return ModelTurn()

    def on_response(self, view, response, state):
        from agent.core.orchestration.completion import REMINDER, completion_text
        calls = response.tool_calls or parse_xml_tool_calls(response.content)
        if calls:
            return ToolBatch(tuple(calls), native=bool(response.tool_calls))
        visible, complete = completion_text(response.content)
        return Complete(visible) if complete else Continue(reminder=REMINDER)

    def on_result(self, view, result, state):
        return state

    def on_event(self, view, event, state):
        return state
