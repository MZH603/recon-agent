"""Compatibility alias for tools.techniques.api_extract."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.techniques.api_extract")
