"""Compatibility alias for the canonical model service module."""
import importlib as _importlib
import sys as _sys

_sys.modules[__name__] = _importlib.import_module("model.service")
