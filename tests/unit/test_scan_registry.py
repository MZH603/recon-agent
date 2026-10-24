import asyncio

import pytest

from agent.gate.scan_gate import ScanGate
from agent.tools.runtime.execution_wait import ToolWaiter
from agent.tools.registry import build_default
from agent.utils.config import Settings


def test_default_registry_builds_builtin_scan_tools(tmp_path):
    settings = Settings()
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, auth_dir=tmp_path)

    registry = build_default(settings, gate, "example.com")

    assert {
        "subdomain_enum",
        "nmap_scan",
        "deep_fingerprint",
        "dir_enum",
        "script_probe",
    }.issubset(registry.names())
    asyncio.run(registry.aclose())


def test_registry_registers_custom_and_enabled_optional_integrations(tmp_path):
    settings = Settings(
        custom_tools=[{"name": "custom", "kind": "command", "command": ["echo", "{target}"]}],
        mcp_servers=[{
            "name": "browser",
            "transport": "stdio",
            "command": "node",
            "args": ["browser-mcp.js"],
            "enabled": True,
            "allowed_tools": ["navigate"],
            "target_fields": {"navigate": ["url"]},
        }],
        extension_tools={
            "scanners": [{"kind": "katana", "enabled": True}],
            "search": {"enabled": True, "provider": "exa"},
            "caido": {"enabled": True},
        },
    )
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, auth_dir=tmp_path)

    registry = build_default(settings, gate, "example.com")
    assert {
        "custom", "mcp_tools", "mcp_call", "katana_crawl", "web_search",
        "web_get_contents", "list_requests", "view_request", "list_sitemap",
    }.issubset(registry.names())
    assert registry.get("katana_crawl").deferred
    assert registry.get("katana_crawl").min_level == 2
    asyncio.run(registry.aclose())


def test_registry_rejects_custom_tool_collisions_with_builtin(tmp_path):
    settings = Settings(
        custom_tools=[{"name": "dns_query", "kind": "command", "command": ["echo"]}]
    )
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, auth_dir=tmp_path)

    with pytest.raises(ValueError, match="dns_query"):
        build_default(settings, gate, "example.com")


def test_subdomain_enumeration_has_a_bounded_extended_timeout():
    settings = Settings()
    waiter = ToolWaiter(settings)
    tool = type("SubdomainTool", (), {"name": "subdomain_enum"})()

    assert waiter.timeout_for(tool, None) == settings.SUBDOMAIN_ENUM_TIMEOUT_SECONDS

    settings.TOOL_TIMEOUT_OVERRIDES["subdomain_enum"] = 240
    assert waiter.timeout_for(tool, None) == 240
