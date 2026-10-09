"""Compatibility alias for tools.adapters.integration_config."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.adapters.integration_config")
