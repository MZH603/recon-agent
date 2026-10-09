"""Compatibility alias for tools.builtin.subdomain_enum."""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("tools.builtin.subdomain_enum")
