"""Compatibility alias for tools.adapters.offline_status."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.adapters.offline_status")
