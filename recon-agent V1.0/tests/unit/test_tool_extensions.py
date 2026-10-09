import asyncio
import json

import pytest
from typer.testing import CliRunner

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.base import ToolResult
from tools.registry import build_default
from utils.config import Settings


def settings_for(tmp_path, **config):
    return Settings(TOOL_EVIDENCE_DIR=str(tmp_path / 'evidence'),
        extension_tools={'workspace': {'directory': str(tmp_path / 'records')}, **config})


def test_default_registration_is_idle_and_external_capabilities_are_opt_in(tmp_path):
    settings = settings_for(tmp_path)
    registry = build_default(settings, ScanGate('example.com', auth_dir=tmp_path / 'auth'), 'example.com')
    assert {'load_skill', 'skill_catalog', 'recon_note', 'recon_finding', 'workspace_snapshot'} <= set(registry.names())
    assert not {'katana_crawl', 'web_search', 'list_requests'} & set(registry.names())
    assert not (tmp_path / 'records').exists() and not (tmp_path / 'evidence').exists()
    asyncio.run(registry.aclose())


def test_profile_loader_and_startup_selection_support_extensions_without_gate_changes(tmp_path):
    from cli.setup_tools import apply_tools_selection, inspect_tools
    from tools.adapters.integration_loader import load_tools_config
    path = tmp_path / 'tools.yaml'
    path.write_text('extension_tools:\n  scanners:\n    - kind: katana\n      enabled: false\n  search:\n    enabled: false\n    provider: exa\n  caido:\n    enabled: false\n', encoding='utf-8')
    settings = settings_for(tmp_path)
    loaded = load_tools_config(settings, path)
    assert loaded.extension_tools.scanners[0].kind == 'katana'
    choices = inspect_tools(settings, str(path))
    assert {'extension:katana', 'extension:search', 'extension:caido'} <= {item['id'] for item in choices['tools']}
    chosen = apply_tools_selection(settings, str(path), ['extension:katana'])
    assert chosen.extension_tools.scanners[0].enabled and not chosen.extension_tools.search.enabled
    assert not chosen.extension_tools.caido.enabled and chosen.GATE_PER_STEP_CONFIRM
    assert not loaded.extension_tools.scanners[0].enabled
    with pytest.raises(ValueError):
        apply_tools_selection(settings, str(path), ['extension:unknown'])
    from cli.main import app
    result = CliRunner().invoke(app, ['--tools-config', str(path), '--list-tools'])
    assert result.exit_code == 0 and 'katana' in result.output and 'disabled' in result.output


def test_latest_workspace_snapshot_report_restores_complete_evidence_after_compression(tmp_path):
    from output.session_report import save_session_report
    async def scenario():
        settings = settings_for(tmp_path)
        settings.TOOL_RESULT_MAX_BYTES = 1024
        gate = ScanGate('example.com', auth_dir=tmp_path / 'auth')
        registry = build_default(settings, gate, 'example.com', session_id='report-session')
        evidence = registry.get('recon_finding').store.evidence
        source = evidence.put('example.com', 'fixture', {'status': 200})
        first = await registry.execute(NormalizedToolCall(id='one', name='recon_finding', arguments={
            'target': 'example.com', 'action': 'create', 'title': 'Old candidate', 'content': 'x' * 7000,
            'evidence_ids': [source]}))
        assert first.success and first.raw_artifact_id
        # The model sees only a preview; storage and final report need the complete record.
        snapshot = await registry.get('workspace_snapshot').run(registry.get('workspace_snapshot').params_model(target='example.com'))
        identifier = snapshot.data['workspace']['findings'][0]['id']
        final = await registry.execute(NormalizedToolCall(id='two', name='recon_finding', arguments={
            'target': 'example.com', 'action': 'update', 'record_id': identifier, 'title': 'Current candidate'}))
        assert final.success
        paths = save_session_report({'target': 'example.com', 'session_id': 'report-session', 'status': 'completed',
            'results': [first.model_dump(), final.model_dump()]}, out_dir=tmp_path / 'reports')
        report = json.loads(paths['json'].read_text(encoding='utf-8'))['report']
        assert len(report['findings']) == 1 and report['findings'][0]['title'] == 'Current candidate'
        assert len(report['findings'][0]['content']) == 7000
        assert report['findings'][0]['status'] == 'candidate'
        assert 'Current candidate' in paths['markdown'].read_text(encoding='utf-8')
        assert 'finding' in paths['csv'].read_text(encoding='utf-8')
        deleted = await registry.execute(NormalizedToolCall(id='three', name='recon_finding', arguments={
            'target': 'example.com', 'action': 'delete', 'record_id': identifier}))
        paths = save_session_report({'target': 'example.com', 'session_id': 'report-session', 'status': 'completed',
            'results': [first.model_dump(), final.model_dump(), deleted.model_dump()]}, out_dir=tmp_path / 'reports')
        assert json.loads(paths['json'].read_text(encoding='utf-8'))['report']['findings'] == []
        await registry.aclose()
    asyncio.run(scenario())


def test_scanner_results_map_to_asset_ports_and_candidates(tmp_path):
    from output.session_report import build_session_report
    results = [ToolResult(name='subfinder_enum', success=True, data={'subdomains': ['api.example.com']}),
        ToolResult(name='naabu_scan', success=True, data={'open_ports': [443]}),
        ToolResult(name='katana_crawl', success=True, data={'endpoints': [
            {'method': 'GET', 'path': '/api', 'params': [], 'source': 'fixture', 'observed': True}]}),
        ToolResult(name='nuclei_scan', success=True, data={'findings': [{'title': 'Template match', 'severity': 'info', 'status': 'candidate'}]})]
    data, _, _, _ = build_session_report({'target': 'example.com', 'status': 'completed',
        'results': [item.model_dump() for item in results]}, 2)
    assert data.subdomains == ['api.example.com'] and data.port_map['example.com'] == [443]
    assert data.api_endpoints[0]['path'] == '/api'
    assert data.findings[0]['status'] == 'candidate'


def snapshot_result(tmp_path, session, title, execution_id):
    from tools.runtime.evidence_store import EvidenceStore
    store = EvidenceStore(tmp_path / 'evidence')
    identifier = store.put('example.com', 'workspace_snapshot', {
        'session_id': session, 'workspace': {'findings': [{'title': title}] if title else []}})
    return dict(ToolResult(name='workspace_snapshot', success=True, data={'target': 'example.com'},
        source_hash=store.get(identifier, target='example.com')['sha256'], artifacts=[{
            'kind': 'workspace_snapshot', 'evidence_id': identifier,
            'path': str(tmp_path / 'evidence' / (identifier + '.json'))}]).model_dump(), execution_id=execution_id)


def test_report_uses_execution_chronology_after_task_results_reset(tmp_path):
    from output.session_report import build_session_report
    old = snapshot_result(tmp_path, 'own', 'Withdrawn finding', 'old')
    deleted = snapshot_result(tmp_path, 'own', '', 'new')
    data, _, _, observations = build_session_report({'target': 'example.com', 'session_id': 'own',
        'status': 'completed', 'results': [deleted], 'executions': [
            {'execution_id': 'old', 'status': 'completed', 'result': old},
            {'execution_id': 'new', 'status': 'completed', 'result': deleted}]}, 0)
    assert data.findings == []
    assert [item['execution_id'] for item in observations] == ['old', 'new']


def test_foreign_snapshot_does_not_clear_current_session_records(tmp_path):
    from output.session_report import build_session_report
    own = snapshot_result(tmp_path, 'own', 'Current finding', 'own')
    foreign = snapshot_result(tmp_path, 'foreign', 'Foreign finding', 'foreign')
    data, _, _, _ = build_session_report({'target': 'example.com', 'session_id': 'own',
        'status': 'completed', 'results': [own, foreign]}, 0)
    assert [item['title'] for item in data.findings] == ['Current finding']


def test_proxy_parameter_names_survive_structured_report_mapping():
    from output.session_report import build_session_report
    result = ToolResult(name='list_requests', success=True, data={'result': {'requests': [
        {'url': 'https://example.com/api', 'method': 'GET', 'status': 200, 'params': ['page', 'token']}]}})
    data, _, _, _ = build_session_report({'target': 'example.com', 'status': 'completed',
        'results': [result.model_dump()]}, 0)
    assert data.api_endpoints[0]['params'] == ['page', 'token']
