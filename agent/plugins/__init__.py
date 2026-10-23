"""Trusted, explicitly enabled in-process plugin API."""

from agent.plugins.api import PluginManifest, ToolProvider
from agent.plugins.host import PluginHost

__all__ = ['PluginManifest', 'ToolProvider', 'PluginHost']
