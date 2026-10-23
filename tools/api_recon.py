"""Compatibility alias for tools.builtin.api_recon."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.api_recon")
