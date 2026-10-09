"""Bounded same-origin JavaScript/API candidates with local evidence provenance."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from security.stealth import StealthRateLimiter
from tools.techniques.api_extract import extract_api_records, javascript_assets, _unique_records
from tools.base import BaseTool, ToolResult
from tools.runtime.evidence_store import EvidenceStore
from tools.adapters.integration_http import guarded_http_get
from utils.config import Settings, get_settings


class ApiReconParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(..., min_length=1, max_length=2048)
    runtime_evidence_ids: list[str] = Field(default_factory=list, max_length=16)

    @field_validator('runtime_evidence_ids')
    @classmethod
    def evidence_ids(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r'[a-fA-F0-9]{64}', value) for value in values):
            raise ValueError('Runtime evidence must use content-addressed SHA256 IDs')
        return list(dict.fromkeys(values))


def _entry_url(target: str) -> str:
    url = target if target.lower().startswith(('http://', 'https://')) else 'https://' + target
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
        raise ValueError('API entry must be an HTTP(S) URL without credentials')
    _ = parts.port
    return urlunsplit((parts.scheme, parts.netloc, parts.path or '/', parts.query, ''))


def _origin(url: str) -> tuple:
    parts = urlsplit(url)
    return parts.scheme.lower(), (parts.hostname or '').lower().rstrip('.'), parts.port or (443 if parts.scheme == 'https' else 80)


def _same_origin(url: str, entry: str) -> bool:
    try:
        parts = urlsplit(url)
        return not (parts.username or parts.password) and _origin(url) == _origin(entry)
    except ValueError:
        return False


def _public_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))


MAX_RUNTIME_SAMPLES = 1000


def _candidate(container: object) -> bool:
    return isinstance(container, dict) and (container.get('observed') is False or
        any(container.get(key) for key in ('mocked', 'mock', 'is_mock', 'from_mock', 'candidate', 'isError')))


def _request_samples(payload: object, *, allow_network_text: bool = False,
                     max_samples: int = MAX_RUNTIME_SAMPLES, limits: dict | None = None) -> list[dict]:
    """Bound sample imports and inherit candidate markers at every container."""
    if not isinstance(payload, dict):
        return []
    limits = limits if limits is not None else {}
    samples: list[dict] = []
    result = payload.get('result')
    inherited = _candidate(payload) or _candidate(result)

    def add_arrays(container, parent_candidate=inherited):
        candidate = parent_candidate or _candidate(container)
        arrays = [container] if isinstance(container, list) else [container.get(key) for key in ('requests', 'network_requests')] if isinstance(container, dict) else []
        for array in arrays:
            if not isinstance(array, list):
                continue
            remaining = max(0, max_samples - len(samples))
            if len(array) > remaining:
                limits['truncated'] = True
            for item in array[:remaining]:
                if isinstance(item, dict):
                    samples.append(dict(item, observed=False) if candidate else item)

    add_arrays(payload)
    if isinstance(result, dict):
        add_arrays(result)
        add_arrays(result.get('structuredContent'))
        for content in result.get('content', []) if isinstance(result.get('content'), list) else []:
            if not isinstance(content, dict) or not isinstance(content.get('text'), str):
                continue
            candidate = inherited or _candidate(content)
            try:
                add_arrays(json.loads(content['text']), candidate)
            except (ValueError, TypeError):
                if allow_network_text:
                    pattern = r'^\s*(?:\d+[.)]\s*)?\[(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\]\s+(https?://\S+?)(?:\s+=>\s+\[(\d{3})\].*)?\s*$'
                    for match in re.finditer(pattern, content['text'], re.M):
                        if len(samples) >= max_samples:
                            limits['truncated'] = True
                            break
                        sample = {'method': match.group(1), 'url': match.group(2),
                                  'status': int(match.group(3)) if match.group(3) else None}
                        if candidate:
                            sample['observed'] = False
                        samples.append(sample)
    return samples


class ApiReconTool(BaseTool):
    name = 'api_recon'
    description = '有界采集同源页面和 JS 懒加载资源，保留 API 候选及本地浏览器请求证据'
    risk_level = '低'
    min_level = 1
    deferred = True
    cacheable = False
    params_model = ApiReconParams

    def __init__(self, settings: Settings | None = None, evidence_store: EvidenceStore | None = None) -> None:
        self._settings = settings or get_settings()
        self._store = evidence_store or EvidenceStore(getattr(self._settings, 'TOOL_EVIDENCE_DIR', None))
        self._limiter = StealthRateLimiter(self._settings.REQUEST_DELAY_RANGE, self._settings.MAX_CONCURRENCY)

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, ApiReconParams)
        try:
            return await self._collect(params)
        except (ValueError, OSError, EOFError, TimeoutError, asyncio.TimeoutError) as exc:
            return ToolResult.err(self.name, f'API collection failed: {exc}')
        except Exception:
            return ToolResult.err(self.name, 'API collection failed: invalid response or local evidence')

    async def _fetch(self, url: str, entry: str, deadline: float, byte_limit: int, remaining_requests: int) -> dict:
        async with self._limiter.slot():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Collection deadline reached')
            return await guarded_http_get(url, entry, settings=self._settings,
                timeout=min(self._settings.CONNECT_TIMEOUT, remaining), max_bytes=byte_limit,
                max_redirects=min(3, remaining_requests - 1), strict_origin=True)

    async def _collect(self, params: ApiReconParams) -> ToolResult:
        entry = _entry_url(params.target)
        deadline = time.monotonic() + min(120, max(1, getattr(self._settings, 'API_RECON_TIMEOUT_SECONDS', 30)))
        request_limit = min(8, max(1, getattr(self._settings, 'API_RECON_MAX_REQUESTS', 8)))
        byte_limit = min(100_000, max(1, getattr(self._settings, 'API_RECON_MAX_ASSET_BYTES', 100_000)))
        endpoints: list[dict] = []
        routes: set[str] = set()
        evidence_ids = list(params.runtime_evidence_ids)
        limitations = ['Static parsing is heuristic; candidates do not prove server accessibility or required parameters.']
        runtime_limits = {}
        runtime_count = 0
        for evidence_id in params.runtime_evidence_ids:
            record = self._store.get(evidence_id, target=params.target)
            payload = record['payload']
            allow_text = record['kind'] in ('mcp_call', 'mcp', 'mcp_response') and isinstance(payload, dict) and payload.get('tool') == 'browser_network_requests'
            samples = _request_samples(payload, allow_network_text=allow_text, max_samples=MAX_RUNTIME_SAMPLES - runtime_count, limits=runtime_limits)
            runtime_count += len(samples)
            for sample in samples:
                request = sample.get('request') if isinstance(sample.get('request'), dict) else {}
                url = sample.get('url') or request.get('url')
                if not isinstance(url, str) or not _same_origin(url, entry):
                    continue
                parts = urlsplit(url)
                method = sample.get('method') or request.get('method')
                if not isinstance(method, str):
                    method = None
                else:
                    method = method.upper() if method.upper() in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE') else None
                names = {key for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
                if isinstance(sample.get('params'), dict):
                    names.update(key for key in sample['params'] if isinstance(key, str))
                elif isinstance(sample.get('params'), list):
                    names.update(item for item in sample['params'] if isinstance(item, str))
                mocked = any(sample.get(key) for key in ('mocked', 'mock', 'is_mock', 'from_mock', 'route_fulfilled', 'candidate'))
                observed = sample.get('observed') is not False and not mocked and (sample.get('status') is not None or sample.get('status_code') is not None or sample.get('observed') is True)
                endpoints.append({'method': method, 'path': parts.path or '/', 'params': sorted(names),
                                  'source': f'evidence:{evidence_id}', 'observed': observed})
        queue = [entry]
        seen: set[str] = set()
        assets = []
        count = 0
        truncated = bool(runtime_limits.get('truncated'))
        if truncated:
            limitations.append('Runtime sample limit reached; complete imported evidence remains available by ID.')
        degraded = False
        while queue and count < request_limit:
            url = queue.pop(0)
            if url in seen or not _same_origin(url, entry):
                continue
            seen.add(url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                truncated = True
                limitations.append('Collection deadline reached.')
                break
            try:
                response = await asyncio.wait_for(
                    self._fetch(url, entry, deadline, byte_limit, request_limit - count), remaining)
            except (ValueError, OSError, EOFError, TimeoutError, asyncio.TimeoutError) as exc:
                count += min(request_limit - count, max(0, getattr(exc, 'request_count', min(4, request_limit - count))))
                if not assets and not endpoints:
                    raise
                truncated = True
                limitations.append('A static request failed or was rejected by scope/deadline guards; existing findings were retained.')
                if not assets:
                    break
                continue
            count += response['request_count']
            final_url = response['url']
            if not _same_origin(final_url, entry):
                raise ValueError('Response origin is outside API collection scope')
            if response['status_code'] >= 400:
                degraded = True
                limitations.append(f"HTTP {response['status_code']} content yields candidates only; endpoint availability is unverified.")
            body = response['body']
            source_hash = hashlib.sha256(body).hexdigest()
            evidence_id = self._store.put(params.target, self.name, {
                'url': final_url, 'method': 'GET', 'status': response['status_code'],
                'headers': response['headers'], 'body': body.decode('utf-8', errors='replace'),
                'source_hash': source_hash, 'observed': True, 'truncated': response['truncated'],
            })
            evidence_ids.append(evidence_id)
            seen.add(final_url)
            assets.append({'url': _public_url(final_url), 'status': response['status_code'],
                           'source_hash': source_hash, 'evidence_id': evidence_id, 'truncated': response['truncated']})
            truncated |= response['truncated']
            text = body.decode('utf-8', errors='replace')
            parser_limits = {}
            parsed, frontend = extract_api_records(text, _public_url(final_url), limits=parser_limits)
            endpoints.extend(parsed)
            routes.update(frontend)
            is_html = 'html' in response['headers'].get('content-type', '').lower() or '<script' in text.lower()
            for asset_url in javascript_assets(text, final_url, html=is_html, limits=parser_limits):
                if asset_url not in seen and asset_url not in queue and _same_origin(asset_url, entry):
                    queue.append(asset_url)
            if parser_limits.get('truncated'):
                truncated = True
                limitations.append('Static parser span/item limits reached; raw source evidence remains available by ID.')
        if queue:
            truncated = True
            limitations.append('Request budget reached; additional JavaScript assets were not fetched.')
        data = {'endpoints': _unique_records(endpoints), 'frontend_routes': sorted(routes), 'assets': assets,
                'evidence_ids': evidence_ids, 'request_count': count, 'truncated': truncated, 'limitations': limitations}
        digest = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        return ToolResult(name=self.name, success=True, data=data,
                          evidence=[f'evidence:{item}' for item in evidence_ids], source_hash=digest,
                          degraded=truncated or degraded, confidence=0.6 if truncated or degraded else 0.8)
