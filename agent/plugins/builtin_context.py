"""Built-in context contribution providing the existing task/evidence index."""
from __future__ import annotations

from agent.plugins.api import PluginManifest
from agent.plugins.context import ContextBlock


class BuiltinContext:
    manifest = PluginManifest(id='builtin-context', version='1.0', api_version='1.0',
                              capabilities=('context',))
    required = True

    def register(self, host, validated_config):
        pass

    async def start(self, session_view):
        pass

    async def close(self):
        pass

    def collect(self, view):
        return [ContextBlock(id='task', source=self.manifest.id, trust='internal',
                             priority=100, content=view.task_summary, required=True)]
