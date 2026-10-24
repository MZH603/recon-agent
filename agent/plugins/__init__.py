"""Trusted, explicitly enabled in-process plugin API."""

from agent.plugins.api import PluginManifest, ToolProvider
from agent.plugins.host import PluginHost
from agent.plugins.context import ContextBlock, ContextProvider, ContextView

__all__ = ['PluginManifest', 'ToolProvider', 'PluginHost', 'ContextBlock',
           'ContextProvider', 'ContextView']
