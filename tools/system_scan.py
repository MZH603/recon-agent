"""Compatibility alias for tools.builtin.system_scan."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.system_scan")
