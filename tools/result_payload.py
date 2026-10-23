"""Compatibility alias for tools.runtime.result_payload."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.runtime.result_payload")
