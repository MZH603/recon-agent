"""Compatibility alias for tools.builtin.wayback_urls."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.wayback_urls")
