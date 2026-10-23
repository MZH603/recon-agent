"""Code-owned discovery and L2 invocation adapters for trusted MCP connectors."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

from jsonschema import validators
from pydantic import BaseModel, ConfigDict, Field

from security.stealth import allowed_target, is_in_scope
from tools.base import BaseTool, ToolResult
from tools.runtime.evidence_store import EvidenceStore, canonical_json
from tools.adapters.integration_config import MCPServerConfig
from tools.adapters.mcp_client import MCPClient, MCPError


class MCPToolsParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(..., min_length=1, max_length=2048)
    server: str = Field(..., min_length=1, max_length=128)


class MCPCallParams(MCPToolsParams):
    tool: str = Field(..., min_length=1, max_length=256)
    arguments: dict = Field(default_factory=dict)


class MCPManager:
    """Shared registry owner. Each instance belongs to one asynchronous session."""
    def __init__(self, settings, main_target, configs):
        self.settings = settings
        self.main_target = main_target
        self.configs = {config.name: config for config in configs}
        self.clients = {}
        self.store = EvidenceStore(getattr(settings, 'TOOL_EVIDENCE_DIR', None) or None)
        self._closed = False
        self._loop = None
        self._targets = {}

    def client(self, server, target):
        loop = asyncio.get_running_loop()
        if self._closed:
            raise MCPError('MCP registry is closed')
        if self._loop is not None and self._loop is not loop:
            raise MCPError('MCP registry cannot be shared across event loops')
        self._loop = loop
        config = self.configs.get(server)
        if config is None:
            raise MCPError('Unknown or disabled MCP server')
        bound = _target_host(target).lower().rstrip('.')
        if server in self._targets and self._targets[server] != bound:
            raise MCPError('Stateful MCP connector is bound to a different invocation target')
        self._targets[server] = bound
        if server not in self.clients:
            self.clients[server] = MCPClient(config)
        return self.clients[server], config

    def check_target(self, target):
        _target_host(target)
        ok, _ = allowed_target(target, self.settings)
        if not ok:
            raise MCPError('MCP target rejected by compliance policy')
        if not is_in_scope(target, self.main_target):
            raise MCPError('MCP target is outside the declared scan scope')

    def redact(self, value, config):
        secrets = {os.environ.get(name, '') for name in list(config.env.values()) + list(config.headers_env.values())}
        secrets.discard('')
        def clean(item):
            if isinstance(item, str):
                for secret in sorted(secrets, key=len, reverse=True):
                    item = item.replace(secret, '[REDACTED]')
                return item
            if isinstance(item, list):
                return [clean(x) for x in item]
            if isinstance(item, dict):
                return {clean(str(k)):clean(v) for k,v in item.items()}
            return item
        return clean(value)

    async def aclose(self):
        if self._closed:
            return
        self._closed = True
        await asyncio.gather(*(client.aclose() for client in self.clients.values()), return_exceptions=True)


def _target_host(value):
    if not isinstance(value, str) or not value or value != value.strip() or any(c.isspace() for c in value):
        raise MCPError('Target policy requires a URL or hostname')
    # Bare IPv6 is a valid host; URLs may only use HTTP(S), without userinfo.
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    parsed = urlsplit(value if '://' in value else '//' + value)
    if ('://' in value and parsed.scheme not in {'http','https'}) or parsed.username or parsed.password or not parsed.hostname:
        raise MCPError('Target policy requires an HTTP(S) URL or hostname without credentials')
    try:
        parsed.port
        host = parsed.hostname.encode('idna').decode('ascii')
    except (ValueError, UnicodeError):
        raise MCPError('Invalid target host or port') from None
    if not re.fullmatch(r'[a-zA-Z0-9._:-]+', host) or host.startswith('.'):
        raise MCPError('Invalid target hostname')
    if '://' not in value and (parsed.path or parsed.query or parsed.fragment):
        raise MCPError('Target policy requires a URL or hostname')
    return host


def _validate_arguments(schema, arguments):
    def inspect(item):
        if isinstance(item, dict):
            if '$ref' in item and (not isinstance(item['$ref'], str) or not item['$ref'].startswith('#')):
                raise MCPError('External remote schema references are not permitted')
            if '$dynamicRef' in item and (not isinstance(item['$dynamicRef'],str) or not item['$dynamicRef'].startswith('#')):
                raise MCPError('External remote schema references are not permitted')
            for value in item.values():
                inspect(value)
        elif isinstance(item, list):
            for value in item:
                inspect(value)
    inspect(schema)
    try:
        validator = validators.validator_for(schema)
        validator.check_schema(schema)
        validator(schema).validate(arguments)
    except Exception:
        raise MCPError('Arguments do not satisfy the advertised remote JSON Schema') from None


def _capture_markers(result):
    """Preserve enclosing candidate/mock markers without duplicating large request arrays."""
    values = [result, result.get('structuredContent')]
    for content in (result.get('content', []) if isinstance(result.get('content', []), list) else []):
        if isinstance(content, dict) and content.get('type') == 'text':
            try:
                values.append(json.loads(content.get('text','')))
            except (ValueError, TypeError):
                pass
    records = {}
    for value in values:
        if isinstance(value, dict):
            for key in ('mocked','mock','is_mock','from_mock','observed','candidate'):
                if key in value:
                    if key == 'observed':
                        records[key] = records.get(key, True) is not False and value[key] is not False
                    else:
                        records[key] = bool(records.get(key)) or bool(value[key])
    return records


def _error_result(manager, name, params, exc):
    result = ToolResult.err(name, str(exc) if isinstance(exc, MCPError) else 'MCP operation failed; remote outcome may be unknown')
    result.outcome_unknown = getattr(exc, 'outcome_unknown', False) or 'unknown' in result.error.lower()
    response = exc.response if isinstance(exc, MCPError) else None
    config = manager.configs.get(params.server)
    if response is not None and config is not None:
        try:
            raw = json.dumps(response, sort_keys=True, ensure_ascii=False).encode('utf-8')
            if len(raw) <= config.max_output_bytes:
                clean = manager.redact(response, config)
                evidence_id = manager.store.put(params.target, 'mcp', {'server':config.name,
                    'tool':getattr(params, 'tool', 'tools/list'), 'result':clean})
                result.data = {'server':config.name, 'evidence_id':evidence_id}
                result.evidence = [f'local-evidence:{evidence_id}']
                result.source_hash = hashlib.sha256(raw).hexdigest()
        except Exception:
            pass  # The safe failure remains explicit even if evidence storage is unavailable.
    return result


class MCPToolsTool(BaseTool):
    name = 'mcp_tools'
    description = '发现已配置 MCP 服务的远端工具 Schema 和执行许可（连接器须预先安装）'
    params_model = MCPToolsParams
    min_level = 0
    deferred = True

    def __init__(self, manager):
        self.manager = manager
        self.deferred = all(config.deferred for config in manager.configs.values())

    async def run(self, params):
        try:
            self.manager.check_target(params.target)
            client, config = self.manager.client(params.server, params.target)
            tools = await client.list_tools()
            visible = []
            for tool in tools:
                item = self.manager.redact(tool, config)
                item['allowed'] = tool['name'] in config.allowed_tools and tool['name'] in config.target_fields
                visible.append(item)
            raw = json.dumps(visible, ensure_ascii=False, sort_keys=True).encode()
            if len(raw) > config.max_output_bytes:
                raise MCPError('MCP discovery exceeds output limit')
            return ToolResult(name=self.name, success=True, data={'server':config.name,'tools':visible},
                              source_hash=hashlib.sha256(raw).hexdigest(), evidence=[f'MCP schema discovery: {config.name}'])
        except asyncio.CancelledError:
            await self.manager.aclose()
            raise
        except Exception as exc:
            return _error_result(self.manager, self.name, params, exc)

    async def aclose(self):
        await self.manager.aclose()


class MCPCallTool(BaseTool):
    cacheable = False
    name = 'mcp_call'
    description = '调用显式允许的远端 MCP 工具，按远端 Schema 和目标策略校验并保存本地证据'
    params_model = MCPCallParams
    min_level = 2
    risk_level = '高'
    deferred = True

    def __init__(self, manager):
        self.manager = manager
        self.deferred = all(config.deferred for config in manager.configs.values())

    async def run(self, params):
        try:
            self.manager.check_target(params.target)
            config = self.manager.configs.get(params.server)
            if config is None:
                raise MCPError('Unknown or disabled MCP server')
            if params.tool not in config.allowed_tools:
                raise MCPError('Remote tool is not explicitly allowed')
            if params.tool not in config.target_fields:
                raise MCPError('Remote tool has no explicit reviewed target policy')
            for field in config.target_fields[params.tool]:
                value = params.arguments.get(field)
                _target_host(value)
                self.manager.check_target(value)
                if not is_in_scope(value, params.target):
                    raise MCPError('Remote tool argument is outside this invocation target')
            client, config = self.manager.client(params.server, params.target)
            schemas = await client.list_tools()
            schema = next((t['inputSchema'] for t in schemas if t['name'] == params.tool), None)
            if schema is None:
                raise MCPError('Remote tool was not advertised by this MCP server')
            _validate_arguments(schema, params.arguments)
            result = await client.call_tool(params.tool, params.arguments)
            raw = canonical_json(result)
            if len(raw) > min(config.max_output_bytes, 2097152 - 4096):
                raise MCPError('Remote tool result exceeds output limit')
            clean = self.manager.redact(result, config)
            payload = {'server':config.name,'tool':params.tool,'result':clean, **_capture_markers(clean)}
            evidence_id = self.manager.store.put(params.target, 'mcp', payload)
            failed = bool(result.get('isError', False))
            return ToolResult(name=self.name, success=not failed, exit_code=1 if failed else 0,
                error='Remote MCP tool reported isError' if failed else '',
                data={'server':config.name, 'tool':params.tool, 'result':clean, 'evidence_id':evidence_id},
                evidence=[f'local-evidence:{evidence_id}'], source_hash=hashlib.sha256(raw).hexdigest())
        except asyncio.CancelledError:
            await self.manager.aclose()
            raise
        except Exception as exc:
            return _error_result(self.manager, self.name, params, exc)

    async def aclose(self):
        await self.manager.aclose()


def build_mcp_tools(settings, main_target):
    configs = [config if isinstance(config, MCPServerConfig) else MCPServerConfig.model_validate(config)
               for config in getattr(settings, 'mcp_servers', [])]
    configs = [config for config in configs if config.enabled]
    if not configs:
        return []
    if len({config.name for config in configs}) != len(configs):
        raise ValueError('Duplicate configured MCP server names')
    manager = MCPManager(settings, main_target, configs)
    return [MCPToolsTool(manager), MCPCallTool(manager)]
