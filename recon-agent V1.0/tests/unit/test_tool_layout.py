"""Legacy tool imports share canonical module state and patch points."""
from importlib import import_module

import pytest


@pytest.mark.parametrize(
    "name,layer,symbol",
    [
        ("catalog", "runtime", "ToolCatalogTool"),
        ("execution_wait", "runtime", "ToolWaiter"),
        ("result_payload", "runtime", "ResultPayloads"),
        ("evidence_store", "runtime", "EvidenceStore"),
        ("evidence_tools", "runtime", "EvidenceGetTool"),
        ("custom", "adapters", "_bounded_process"),
        ("mcp_client", "adapters", "MCPClient"),
        ("mcp_tools", "adapters", "_validate_arguments"),
        ("integration_config", "adapters", "CustomToolConfig"),
        ("integration_http", "adapters", "_request_chain"),
        ("integration_loader", "adapters", "load_tools_config"),
        ("offline_status", "adapters", "_executable_status"),
        ("api_recon", "builtin", "ApiReconTool"),
        ("deep_fingerprint", "builtin", "DeepFingerprintTool"),
        ("dir_enum", "builtin", "DirEnumTool"),
        ("httpx_tool", "builtin", "HttpxProbeTool"),
        ("nmap_tool", "builtin", "NmapTool"),
        ("script_probe", "builtin", "ScriptProbeTool"),
        ("subdomain_enum", "builtin", "certificate_names"),
        ("system_scan", "builtin", "SystemScanTool"),
        ("takeover_check", "builtin", "TakeoverCheckTool"),
        ("wayback_urls", "builtin", "WaybackTool"),
        ("api_extract", "techniques", "_unique_records"),
    ],
)
def test_legacy_imports_share_canonical_module_and_patch_points(name, layer, symbol, monkeypatch):
    legacy = import_module(f"tools.{name}")
    canonical = import_module(f"tools.{layer}.{name}")

    assert legacy is canonical
    assert getattr(legacy, symbol) is getattr(canonical, symbol)
    replacement = object()
    monkeypatch.setattr(legacy, symbol, replacement)
    assert getattr(canonical, symbol) is replacement
