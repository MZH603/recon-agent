"""Compatibility alias for tools.builtin.httpx_tool."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.httpx_tool")
