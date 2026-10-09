"""Compatibility alias for tools.builtin.dir_enum."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.dir_enum")
