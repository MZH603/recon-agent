"""Compatibility alias for tools.runtime.execution_wait."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.runtime.execution_wait")
