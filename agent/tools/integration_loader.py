"""Compatibility alias for tools.adapters.integration_loader."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("agent.tools.adapters.integration_loader")
