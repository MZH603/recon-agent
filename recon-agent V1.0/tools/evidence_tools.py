"""Compatibility alias for tools.runtime.evidence_tools."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.runtime.evidence_tools")
