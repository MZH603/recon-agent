"""Built-in tool provider, including explicitly configured legacy connectors."""
from __future__ import annotations

from agent.plugins.api import PluginManifest


class BuiltinTools:
    manifest = PluginManifest(id='builtin-tools', version='1.0', api_version='1.0',
                              capabilities=('tools',))

    def __init__(self, settings, main_target, session_id=None):
        self.settings = settings
        self.main_target = main_target
        self.session_id = session_id

    def snapshot_config(self):
        """Effective connector settings that change this provider's tool behavior."""
        settings = self.settings
        keys = ('custom_tools', 'mcp_servers', 'extension_tools', 'TOOL_EVIDENCE_DIR',
                'TOOL_TIMEOUT_SECONDS', 'SUBDOMAIN_ENUM_TIMEOUT_SECONDS',
                'TOOL_CLEANUP_SECONDS', 'TOOL_TIMEOUT_OVERRIDES',
                'TOOL_RESULT_MAX_BYTES', 'API_RECON_MAX_REQUESTS',
                'API_RECON_MAX_ASSET_BYTES', 'API_RECON_TIMEOUT_SECONDS')
        values = settings.model_dump(mode='json')
        return {key: values[key] for key in keys}

    def describe_tool_names(self, validated_config):
        """Declare the complete config-dependent catalog without constructing tools."""
        from agent.tools.adapters.scanners import NAMES

        settings = self.settings
        names = [
            'dns_query', 'subdomain_enum', 'fingerprint', 'httpx_probe',
            'nmap_scan', 'builtin_port_scan', 'dir_enum', 'script_probe',
            'deep_fingerprint', 'takeover_check', 'wayback_urls', 'system_scan',
            'api_recon', 'tool_catalog', 'evidence_search', 'evidence_get',
            'artifact_read',
        ]
        names.extend(tool.name for tool in settings.custom_tools if tool.enabled)
        if any(server.enabled for server in settings.mcp_servers):
            names.extend(('mcp_tools', 'mcp_call'))
        names.extend(NAMES[scanner.kind] for scanner in settings.extension_tools.scanners
                     if scanner.enabled)
        search = settings.extension_tools.search
        if search is not None and search.enabled:
            names.append('web_search')
            if search.provider == 'exa':
                names.append('web_get_contents')
        caido = settings.extension_tools.caido
        if caido is not None and caido.enabled:
            names.extend(('list_requests', 'view_request', 'list_sitemap'))
        if settings.extension_tools.knowledge_enabled:
            names.extend(('skill_catalog', 'load_skill'))
        if settings.extension_tools.workspace.enabled:
            names.extend(('recon_note', 'recon_coverage', 'recon_threat_model',
                          'recon_finding', 'workspace_snapshot'))
        return tuple(names)

    def register(self, host, validated_config):
        from agent.tools.builtin.dns_query import DNSQueryTool
        from agent.tools.builtin.fingerprint import FingerprintTool
        from agent.tools.builtin.port_scan import BuiltinPortScan
        from agent.tools.builtin.deep_fingerprint import DeepFingerprintTool
        from agent.tools.builtin.dir_enum import DirEnumTool
        from agent.tools.builtin.httpx_tool import HttpxProbeTool
        from agent.tools.builtin.nmap_tool import NmapTool
        from agent.tools.builtin.script_probe import ScriptProbeTool
        from agent.tools.builtin.subdomain_enum import SubdomainEnumTool
        from agent.tools.builtin.system_scan import SystemScanTool
        from agent.tools.builtin.takeover_check import TakeoverCheckTool
        from agent.tools.builtin.wayback_urls import WaybackTool
        from agent.tools.builtin.api_recon import ApiReconTool
        from agent.tools.adapters.custom import build_custom_tools
        from agent.tools.adapters.mcp_tools import build_mcp_tools
        from agent.tools.adapters.scanners import build_scanner_tools
        from agent.tools.adapters.search import build_search_tools
        from agent.tools.adapters.proxy import build_proxy_tools
        from agent.tools.runtime.evidence_tools import build_evidence_tools
        from agent.tools.runtime.catalog import ToolCatalogTool
        from agent.tools.runtime.knowledge import build_knowledge_tools
        from agent.tools.runtime.workspace import build_workspace_tools

        settings = self.settings
        for cls in (DNSQueryTool, SubdomainEnumTool, FingerprintTool, HttpxProbeTool,
                    NmapTool, BuiltinPortScan, DirEnumTool, ScriptProbeTool,
                    DeepFingerprintTool, TakeoverCheckTool, WaybackTool, SystemScanTool,
                    ApiReconTool):
            host.register_tool(cls(settings))
        host.register_tool(ToolCatalogTool(host.registry))
        for tool in [
            *build_evidence_tools(settings),
            *build_custom_tools(settings),
            *build_mcp_tools(settings, self.main_target),
            *build_scanner_tools(settings),
            *build_search_tools(settings),
            *build_proxy_tools(settings),
            *build_knowledge_tools(settings),
            *build_workspace_tools(settings, self.session_id),
        ]:
            host.register_tool(tool)

    async def start(self, session_view):
        pass

    async def close(self):
        pass
