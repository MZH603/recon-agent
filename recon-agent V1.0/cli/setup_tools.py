"""Bounded, offline extension selection for startup; never execute a tool here."""
from pathlib import Path
import re
import shutil

from tools.adapters.integration_loader import load_tools_config
from tools.adapters.offline_status import _executable_status
from utils.config import Settings
from tools.adapters.extension_inventory import configured_extension_rows as _extension_rows

TOOL_FIELDS = {"tools_config", "selected_tools"}
MAX_TOOLS = 100
MAX_PROFILE_BYTES = 262144
EXAMPLE_PROFILE = Path(__file__).resolve().parents[1] / "tools/data/tool-integrations.example.yaml"


def valid_tools_path(value):
    return (isinstance(value, str) and len(value) <= 2048 and
            all(ord(char) >= 32 and not 127 <= ord(char) <= 159 for char in value))


def valid_tools_fields(payload):
    present = TOOL_FIELDS.intersection(payload)
    if not present:
        return True
    selected = payload.get("selected_tools")
    return (present == TOOL_FIELDS and valid_tools_path(payload.get("tools_config")) and
            isinstance(selected, list) and len(selected) <= MAX_TOOLS and
            all(isinstance(item, str) and re.fullmatch(r"(?:custom|mcp|extension):[A-Za-z][A-Za-z0-9_]{0,63}", item) for item in selected) and
            len(set(selected)) == len(selected))


def _profile(settings, path):
    if not valid_tools_path(path):
        raise ValueError("Invalid profile path")
    cleaned = path.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] == '"':
        cleaned = cleaned[1:-1]
    profile = load_tools_config(settings, Path(cleaned), max_bytes=MAX_PROFILE_BYTES) if cleaned else settings.model_copy(deep=True)
    ids = ["custom:" + item.name for item in profile.custom_tools] + ["mcp:" + item.name for item in profile.mcp_servers]
    ids.extend(row['id'] for row in _extension_rows(profile))
    if len(ids) > MAX_TOOLS or len(set(ids)) != len(ids):
        raise ValueError("Too many or duplicate extension tools")
    return profile


def _rows(profile):
    rows = []
    for item in profile.custom_tools:
        if item.kind == "command":
            status = _executable_status(item.command[0], item.command[1:])
        elif item.kind == "script":
            status = "bandit-found" if shutil.which("bandit") else "requires-bandit"
        else:
            status = "manual-hint" if item.kind == "shell" else "configured-http"
        rows.append(dict(id="custom:" + item.name, name=item.name, kind=item.kind,
                         enabled=item.enabled, min_level=item.min_level, status=status))
    for item in profile.mcp_servers:
        status = _executable_status(item.command, item.args) if item.transport == "stdio" else "configured-http"
        rows.append(dict(id="mcp:" + item.name, name=item.name, kind="mcp:" + item.transport,
                         enabled=item.enabled, min_level=item.min_level, status=status))
    return rows + _extension_rows(profile)


def inspect_tools(settings, path):
    return {"tools_config": path, "tools": _rows(_profile(settings, path))}


def default_tool_options(settings):
    path = "" if settings.custom_tools or settings.mcp_servers or _extension_rows(settings) else str(EXAMPLE_PROFILE)
    try:
        return inspect_tools(settings, path)
    except (OSError, ValueError, UnicodeError, RecursionError):
        # An optional missing/invalid profile can never prevent auth from opening.
        return {"tools_config": "", "tools": []}


def apply_tools_selection(settings, path, selected):
    if not valid_tools_fields({"tools_config": path, "selected_tools": selected}):
        raise ValueError("Invalid tool selection")
    profile = _profile(settings, path)
    known = {row["id"] for row in _rows(profile)}
    if not set(selected).issubset(known):
        raise ValueError("Unknown selected tools")
    for item in profile.custom_tools:
        item.enabled = "custom:" + item.name in selected
    for item in profile.mcp_servers:
        item.enabled = "mcp:" + item.name in selected
    for item in profile.extension_tools.scanners:
        item.enabled = 'extension:' + item.kind in selected
    if profile.extension_tools.search is not None:
        profile.extension_tools.search.enabled = 'extension:search' in selected
    if profile.extension_tools.caido is not None:
        profile.extension_tools.caido.enabled = 'extension:caido' in selected
    # Constructors only create lazy wrappers. The gate is unused until execution;
    # checking registry collisions must not create a session or run a connector.
    from tools.registry import build_default
    build_default(profile, None, "")
    return profile
