"""Compatibility alias for tools.adapters.mcp_tools."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.adapters.mcp_tools")
