"""Compatibility alias for tools.builtin.nmap_tool."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.nmap_tool")
