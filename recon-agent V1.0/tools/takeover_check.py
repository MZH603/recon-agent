"""Compatibility alias for tools.builtin.takeover_check."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.takeover_check")
