"""Compatibility alias for tools.builtin.deep_fingerprint."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.deep_fingerprint")
