"""Bounded local API/JS collection and evidence provenance tests."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from pydantic import ValidationError


def test_static_methods_parameters_routes_and_unknown_method():
    from tools.api_extract import extract_api_records
    text = '''fetch('/api/users?limit=5');
        fetch('/api/create', {method:'POST', body: JSON.stringify({name: value})});
        axios.put('/api/items', {title: name});
        const service='/api/unknown'; const route={path:'/dashboard'};'''
    endpoints, routes = extract_api_records(text, 'https://example.com/app.js')
    by_path = {item['path']: item for item in endpoints}
    assert by_path['/api/users']['method'] == 'GET'
    assert by_path['/api/users']['params'] == ['limit']
    assert by_path['/api/create']['method'] == 'POST'
    assert by_path['/api/create']['params'] == ['name']
    assert by_path['/api/items']['method'] == 'PUT'
    assert by_path['/api/unknown']['method'] is None
    assert all(not item['observed'] for item in endpoints)
    assert '/dashboard' in routes


def test_lazy_vite_and_webpack_assets():
    from tools.api_extract import javascript_assets
    text = '''import('./lazy-ab.js'); __vite__mapDeps([0,1]);
      const deps=['assets/users-x.js','assets/users.css'];
      r.u=e=>({123:'users',456:'profile'}[e])+'.'+({123:'aabb',456:'ccdd'}[e])+'.js';
      r.p='/static/';'''
    assets = javascript_assets(text, 'https://example.com/assets/main.js')
    assert 'https://example.com/assets/lazy-ab.js' in assets
    assert 'https://example.com/assets/users-x.js' in assets
    assert 'https://example.com/static/users.aabb.js' in assets
    assert 'https://example.com/static/profile.ccdd.js' in assets
    assert all(not url.endswith('.css') for url in assets)


@pytest.fixture
def site():
    state = {'pages': {}, 'requests': []}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            state['requests'].append(self.path)
            status, headers, body = state['pages'].get(self.path, (404, {}, b''))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state['url'] = f'http://127.0.0.1:{server.server_port}/'
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def settings(tmp_path, **overrides):
    from utils.config import Settings
    actual = Settings(LAB_MODE=True, REQUEST_DELAY_RANGE=(0, 0), CONNECT_TIMEOUT=2)
    data = dict(actual.__dict__)
    data.update(TOOL_EVIDENCE_DIR=tmp_path / 'evidence', API_RECON_MAX_REQUESTS=8,
                API_RECON_MAX_ASSET_BYTES=100_000, API_RECON_TIMEOUT_SECONDS=10)
    data.update(overrides)
    return SimpleNamespace(**data)


def collect(site, tmp_path, ids=None, **overrides):
    from tools.api_recon import ApiReconParams, ApiReconTool
    return asyncio.run(ApiReconTool(settings(tmp_path, **overrides)).run(
        ApiReconParams(target=site['url'], runtime_evidence_ids=ids or [])))


def test_collects_entry_lazy_chunks_and_keeps_scope(site, tmp_path):
    site['pages'] = {
        '/': (200, {'Content-Type': 'text/html'}, b'<script src="/main.js"></script><script src="http://outside.invalid/evil.js"></script>'),
        '/main.js': (200, {}, b"fetch('/api/users?q=x');import('./lazy.js');"),
        '/lazy.js': (200, {}, b"axios.post('/api/create', {title: value});"),
    }
    result = collect(site, tmp_path)
    assert result.success, result.error
    assert site['requests'] == ['/', '/main.js', '/lazy.js']
    assert {item['path'] for item in result.data['endpoints']} == {'/api/users', '/api/create'}
    assert result.data['request_count'] == 3
    assert len(result.source_hash) == 64
    assert all(len(asset['source_hash']) == 64 for asset in result.data['assets'])
    assert len(result.data['evidence_ids']) == 3


def test_request_budget_and_byte_caps(site, tmp_path):
    site['pages']['/'] = (200, {}, b'<script src="/1.js"></script><script src="/2.js"></script>')
    site['pages']['/1.js'] = (200, {}, b"fetch('/api/small');" + b' ' * 1000)
    result = collect(site, tmp_path, API_RECON_MAX_REQUESTS=2, API_RECON_MAX_ASSET_BYTES=100)
    assert result.success, result.error
    assert site['requests'] == ['/', '/1.js']
    assert result.data['request_count'] == 2
    assert result.data['truncated']
    assert result.data['assets'][1]['truncated']


def test_redirect_scope_rejects_changed_port(site, tmp_path):
    site['pages']['/'] = (302, {'Location': 'http://127.0.0.1:1/other.js'}, b'')
    result = collect(site, tmp_path)
    assert not result.success
    assert 'scope' in result.error.lower() or 'origin' in result.error.lower()
    assert site['requests'] == ['/']


def test_redirects_are_counted_in_total_budget(site, tmp_path):
    site['pages']['/'] = (302, {'Location': '/entry'}, b'')
    site['pages']['/entry'] = (200, {}, b'<script src="/more.js"></script>')
    result = collect(site, tmp_path, API_RECON_MAX_REQUESTS=2)
    assert result.success, result.error
    assert site['requests'] == ['/', '/entry']
    assert result.data['request_count'] == 2
    assert result.data['truncated']


def test_runtime_evidence_observed_and_mock_candidates(site, tmp_path):
    from tools.evidence_store import EvidenceStore
    site['pages']['/'] = (200, {}, b'')
    store = EvidenceStore(tmp_path / 'evidence')
    evidence_id = store.put(site['url'], 'mcp_call', {'requests': [
        {'url': site['url'] + 'api/live?offset=2', 'method': 'PATCH', 'status': 200},
        {'url': site['url'] + 'api/mock', 'method': 'POST', 'mocked': True},
        {'url': 'https://outside.invalid/api/no', 'method': 'GET'},
    ]})
    result = collect(site, tmp_path, [evidence_id])
    assert result.success, result.error
    records = {item['path']: item for item in result.data['endpoints']}
    assert records['/api/live']['observed'] is True
    assert records['/api/live']['params'] == ['offset']
    assert records['/api/mock']['observed'] is False
    assert '/api/no' not in records


def test_runtime_evidence_target_binding_and_id_validation(site, tmp_path):
    from tools.evidence_store import EvidenceStore
    store = EvidenceStore(tmp_path / 'evidence')
    evidence_id = store.put('https://different.example/', 'mcp_call', {'requests': []})
    result = collect(site, tmp_path, [evidence_id])
    assert not result.success
    assert site['requests'] == []
    from tools.api_recon import ApiReconParams
    with pytest.raises(ValidationError):
        ApiReconParams(target=site['url'], runtime_evidence_ids=['../../secret'])


def test_params_cannot_raise_budgets():
    from tools.api_recon import ApiReconParams
    with pytest.raises(ValidationError):
        ApiReconParams(target='https://example.com', max_requests=1000)


def test_foreign_api_literals_do_not_masquerade_as_local_paths():
    from tools.api_extract import extract_api_records
    endpoints, _ = extract_api_records("fetch('https://foreign.example/api/secret');fetch('/api/local');", 'https://example.com/app.js')
    assert [item['path'] for item in endpoints] == ['/api/local']


def test_runtime_mcp_structured_json_and_mock_parent(site, tmp_path):
    from tools.evidence_store import EvidenceStore
    site['pages']['/'] = (200, {}, b'')
    store = EvidenceStore(tmp_path / 'evidence')
    evidence_id = store.put(site['url'], 'mcp_call', {'mocked': True, 'result': {'content': [
        {'type': 'text', 'text': json.dumps({'network_requests': [
            {'url': site['url'] + 'api/from-json', 'method': 'GET', 'status': 200}
        ]})}
    ]}})
    result = collect(site, tmp_path, [evidence_id])
    assert result.success, result.error
    assert result.data['endpoints'][0]['observed'] is False


def test_collection_deadline_stops_before_network(site, tmp_path):
    from tools.api_recon import ApiReconParams, ApiReconTool
    config = settings(tmp_path, API_RECON_TIMEOUT_SECONDS=1, REQUEST_DELAY_RANGE=(2, 2))
    result = asyncio.run(ApiReconTool(config).run(ApiReconParams(target=site['url'])))
    assert not result.success
    assert site['requests'] == []


def test_methods_do_not_leak_between_adjacent_calls():
    from tools.api_extract import extract_api_records
    endpoints, _ = extract_api_records("fetch('/api/a'),fetch('/api/b',{method:'POST'});", 'https://example.com/app.js')
    assert [(item['path'], item['method']) for item in endpoints] == [('/api/a', 'GET'), ('/api/b', 'POST')]


def test_playwright_network_text_is_imported_only_for_network_tool(site, tmp_path):
    from tools.evidence_store import EvidenceStore
    site['pages']['/'] = (200, {}, b'')
    store = EvidenceStore(tmp_path / 'evidence')
    lines = f"1. [GET] {site['url']}api/traffic?token=secret => [200] OK\n2. [POST] {site['url']}api/pending"
    traffic = store.put(site['url'], 'mcp_call', {'tool': 'browser_network_requests', 'result': {'content': [{'type': 'text', 'text': lines}]}})
    prose = store.put(site['url'], 'mcp_call', {'tool': 'browser_snapshot', 'result': {'content': [{'type': 'text', 'text': f'[GET] {site["url"]}api/prose => [200] OK'}]}})
    result = collect(site, tmp_path, [traffic, prose])
    assert result.success, result.error
    by_path = {item['path']: item for item in result.data['endpoints']}
    assert by_path['/api/traffic']['method'] == 'GET'
    assert by_path['/api/traffic']['observed'] is True
    assert by_path['/api/traffic']['params'] == ['token']
    assert by_path['/api/pending']['observed'] is False
    assert '/api/prose' not in by_path
    assert 'secret' not in json.dumps(result.data)


def test_failed_redirect_chains_stay_within_request_budget(site, tmp_path):
    site['pages']['/'] = (200, {}, b'<script src="/a.js"></script><script src="/b.js"></script><script src="/c.js"></script>')
    for name in ('a', 'b', 'c'):
        site['pages'][f'/{name}.js'] = (302, {'Location': f'/{name}1'}, b'')
        site['pages'][f'/{name}1'] = (302, {'Location': f'/{name}2'}, b'')
        site['pages'][f'/{name}2'] = (302, {'Location': 'http://127.0.0.1:1/out'}, b'')
    result = collect(site, tmp_path)
    assert result.success, result.error
    assert len(site['requests']) <= 8
    assert result.data['request_count'] >= len(site['requests'])
    assert result.degraded


def test_http_error_content_stays_candidate_with_limitation(site, tmp_path):
    site['pages']['/'] = (404, {'Content-Type': 'text/html'}, b"<script>fetch('/api/from-error')</script>")
    result = collect(site, tmp_path)
    assert result.success, result.error
    assert result.degraded
    assert result.data['endpoints'][0]['observed'] is False
    assert any('404' in item for item in result.data['limitations'])


def test_root_candidate_marker_stays_candidate(site, tmp_path):
    from tools.evidence_store import EvidenceStore
    site['pages']['/'] = (200, {}, b'')
    evidence_id = EvidenceStore(tmp_path / 'evidence').put(site['url'], 'mcp', {
        'candidate': True, 'requests': [{'url': site['url'] + 'api/candidate', 'method': 'POST', 'status': 200}]})
    result = collect(site, tmp_path, [evidence_id])
    assert result.success, result.error
    assert result.data['endpoints'][0]['observed'] is False


def test_runtime_findings_survive_entry_failure(site, tmp_path, monkeypatch):
    from tools.evidence_store import EvidenceStore
    import tools.api_recon as module
    evidence_id = EvidenceStore(tmp_path / 'evidence').put(site['url'], 'mcp', {
        'requests': [{'url': site['url'] + 'api/retained', 'method': 'GET', 'status': 200}]})
    async def fail(*args, **kwargs):
        raise OSError('offline fixture')
    monkeypatch.setattr(module, 'guarded_http_get', fail)
    result = collect(site, tmp_path, [evidence_id])
    assert result.success, result.error
    assert result.degraded
    assert result.data['endpoints'][0]['path'] == '/api/retained'
    assert any('failed' in note.lower() for note in result.data['limitations'])


@pytest.mark.parametrize('format', ['structured', 'json'])
def test_nested_mock_marker_stays_candidate(site, tmp_path, format):
    from tools.evidence_store import EvidenceStore
    site['pages']['/'] = (200, {}, b'')
    container = {'mocked': True, 'requests': [{'url': site['url'] + 'api/nested', 'method': 'GET', 'status': 200}]}
    result = {'structuredContent': container} if format == 'structured' else {'content': [{'text': json.dumps(container)}]}
    evidence_id = EvidenceStore(tmp_path / 'evidence').put(site['url'], 'mcp', {'result': result})
    collected = collect(site, tmp_path, [evidence_id])
    assert collected.success, collected.error
    assert collected.data['endpoints'][0]['observed'] is False


def test_static_parser_bounded_items_marks_truncation():
    from tools.api_extract import extract_api_records, javascript_assets
    limits = {}
    records, _ = extract_api_records("fetch('/api/x'," * 2000, 'https://example.com/app.js', limits=limits)
    assert len(records) <= 1000
    assert limits['truncated']
    refs = javascript_assets(';'.join(f"import('./{i}.js')" for i in range(1100)), 'https://example.com/app.js', limits=limits)
    assert len(refs) <= 1000


def test_runtime_sample_cap_reports_retained_raw_evidence(site, tmp_path):
    from tools.evidence_store import EvidenceStore
    site['pages']['/'] = (200, {}, b'')
    samples = [{'url': site['url'] + f'api/r{i}', 'method': 'GET', 'status': 200} for i in range(1100)]
    evidence_id = EvidenceStore(tmp_path / 'evidence').put(site['url'], 'mcp', {'requests': samples})
    result = collect(site, tmp_path, [evidence_id])
    assert result.success, result.error
    assert len(result.data['endpoints']) <= 1000
    assert result.data['truncated'] and result.degraded
    assert evidence_id in result.data['evidence_ids']
    assert any('sample' in note.lower() for note in result.data['limitations'])
