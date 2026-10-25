"""Fingerprint signatures loader from external YAML (hot-reloadable)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from utils.config import Settings, get_settings


class FingerprintSignatures:
    """Loaded fingerprint signatures from YAML."""

    def __init__(self, data: dict[str, Any]):
        self.header_signatures = tuple(
            (s["header"], s["regex"], s["category"], s["name"], s["confidence"])
            for s in data.get("header_signatures", [])
        )
        self.version_header_signatures = tuple(
            (s["header"], s["regex"], s["category"], s["name"])
            for s in data.get("version_header_signatures", [])
        )
        self.body_signatures = tuple(
            (s["pattern"], s["category"], s["name"], s["confidence"])
            for s in data.get("body_signatures", [])
        )
        self.security_header_signatures = tuple(
            (s["header"], s["name"])
            for s in data.get("security_header_signatures", [])
        )
        self.script_lib_names = data.get("script_lib_names", {})
        self.script_version_re = re.compile(
            data.get("script_version_regex", r"(jquery|bootstrap|layui|angular|vue|react|echarts|swiper)[\-\.]v?(\d+\.\d+(?:\.\d+)?)"),
            re.I
        )

    @classmethod
    def load_from_yaml(cls, path: Path) -> "FingerprintSignatures":
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    @classmethod
    def load_default(cls) -> "FingerprintSignatures":
        """Load from default location."""
        default_path = Path(__file__).resolve().parents[1] / "data" / "fingerprints.yaml"
        return cls.load_from_yaml(default_path)


# Global cache with optional hot-reload
_signatures_cache: FingerprintSignatures | None = None
_cache_mtime: float | None = None


def get_signatures(settings: Settings | None = None, reload: bool = False) -> FingerprintSignatures:
    """Get fingerprint signatures with optional hot-reload."""
    global _signatures_cache, _cache_mtime

    s = settings or get_settings()
    path = Path(s.TOOL_EVIDENCE_DIR) / "fingerprints.yaml" if s.TOOL_EVIDENCE_DIR else None
    if not path or not path.exists():
        path = Path(__file__).resolve().parents[1] / "data" / "fingerprints.yaml"

    mtime = path.stat().st_mtime if path.exists() else 0
    if _signatures_cache is None or reload or mtime != _cache_mtime:
        _signatures_cache = FingerprintSignatures.load_from_yaml(path)
        _cache_mtime = mtime

    return _signatures_cache


def reload_signatures(settings: Settings | None = None) -> FingerprintSignatures:
    """Force reload signatures from disk."""
    return get_signatures(settings, reload=True)