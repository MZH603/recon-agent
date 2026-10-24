"""Trusted, explicitly enabled in-process plugin API."""

from agent.plugins.api import PluginManifest, ToolProvider
from agent.plugins.host import PluginHost
from agent.plugins.context import ContextBlock, ContextProvider, ContextView
from agent.plugins.loop import (AgentLoop, LoopView, LoopProposal, ModelTurn,
                                ToolBatch, AskUser, Complete, Continue, LoopEvent)

__all__ = ['PluginManifest', 'ToolProvider', 'PluginHost', 'ContextBlock',
           'ContextProvider', 'ContextView', 'AgentLoop', 'LoopView', 'LoopProposal',
           'ModelTurn', 'ToolBatch', 'AskUser', 'Complete', 'Continue', 'LoopEvent']
