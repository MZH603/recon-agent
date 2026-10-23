"""Compatibility alias for tools.adapters.custom."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.adapters.custom")
