"""Compatibility alias for tools.runtime.catalog."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.runtime.catalog")
