"""Compatibility alias for tools.builtin.script_probe."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.script_probe")
