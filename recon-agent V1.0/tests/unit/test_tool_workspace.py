import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from tools.runtime.evidence_store import EvidenceStore


def workspace(tmp_path, session='one'):
    from tools.runtime.workspace import WorkspaceConfig, build_workspace_tools
    settings = SimpleNamespace(TOOL_EVIDENCE_DIR=str(tmp_path / 'evidence'),
        extension_tools=SimpleNamespace(workspace=WorkspaceConfig(directory=str(tmp_path / 'records'))))
    tools = {tool.name: tool for tool in build_workspace_tools(settings, session_id=session)}
    return tools


def invoke(tool, **params):
    return asyncio.run(tool.run(tool.params_model.model_validate(params)))


def test_note_revisions_delete_and_final_snapshot_survive_restart(tmp_path):
    tools = workspace(tmp_path)
    assert not (tmp_path / 'records').exists()
    note = invoke(tools['recon_note'], target='example.com', action='create', title='入口', content='old')
    assert note.success and note.source_hash and note.evidence
    identifier = note.data['record']['id']
    update = invoke(tools['recon_note'], target='example.com', action='update', record_id=identifier, content='new')
    assert update.data['record']['revision'] == 2
    restored = workspace(tmp_path)
    snapshot = invoke(restored['workspace_snapshot'], target='example.com')
    assert snapshot.data['workspace']['notes'][0]['content'] == 'new'
    deleted = invoke(restored['recon_note'], target='example.com', action='delete', record_id=identifier)
    assert deleted.success and deleted.data['workspace']['notes'] == []
    assert invoke(workspace(tmp_path)['workspace_snapshot'], target='example.com').data['workspace']['notes'] == []
    store = EvidenceStore(tmp_path / 'evidence')
    assert store.get(note.data['snapshot_evidence_id'], target='example.com')['payload']['workspace']['notes'][0]['content'] == 'old'
    assert store.get(deleted.data['snapshot_evidence_id'], target='example.com')['payload']['workspace']['notes'] == []


def test_workspace_isolates_sessions_targets_and_rejects_missing_updates(tmp_path):
    tools = workspace(tmp_path)
    created = invoke(tools['recon_note'], target='example.com', action='create', title='A', content='data')
    record_id = created.data['record']['id']
    for other in ('example.net', 'child.example.com'):
        result = invoke(tools['recon_note'], target=other, action='get', record_id=record_id)
        assert not result.success
    result = invoke(workspace(tmp_path, 'two')['recon_note'], target='example.com', action='get', record_id=record_id)
    assert not result.success
    assert not invoke(tools['recon_note'], target='example.com', action='update', record_id='0' * 32, content='oops').success
    assert invoke(tools['workspace_snapshot'], target='example.com').data['workspace']['notes'][0]['content'] == 'data'


def test_finding_requires_same_target_evidence_and_retains_status(tmp_path):
    tools = workspace(tmp_path)
    store = EvidenceStore(tmp_path / 'evidence')
    evidence_id = store.put('example.com', 'fixture', {'status': 200})
    foreign_id = store.put('example.net', 'fixture', {'status': 200})
    args = dict(target='example.com', action='create', title='候选', content='Needs review', severity='low', status='candidate')
    assert not invoke(tools['recon_finding'], **args).success
    assert not invoke(tools['recon_finding'], **args, evidence_ids=[foreign_id]).success
    result = invoke(tools['recon_finding'], **args, evidence_ids=[evidence_id])
    assert result.success and result.data['record']['status'] == 'candidate'
    identifier = result.data['record']['id']
    assert not invoke(tools['recon_finding'], target='example.com', action='update', record_id=identifier, evidence_ids=[foreign_id]).success
    current = invoke(tools['recon_finding'], target='example.com', action='get', record_id=identifier)
    assert current.data['record']['evidence_ids'] == [evidence_id]


def test_coverage_threat_model_and_schema_bounds(tmp_path):
    tools = workspace(tmp_path)
    assert not invoke(tools['recon_coverage'], target='example.com', action='create', surface='/api', risk_area='auth', outcome='verified').success
    coverage = invoke(tools['recon_coverage'], target='example.com', action='create', surface='/api', risk_area='auth', outcome='not_tested')
    assert coverage.success
    model = invoke(tools['recon_threat_model'], target='example.com', action='create', title='Scope', content='Trust boundary')
    assert model.success
    snapshot = invoke(tools['workspace_snapshot'], target='example.com')
    assert len(snapshot.data['workspace']['coverage']) == len(snapshot.data['workspace']['threat_models']) == 1
    with pytest.raises(ValidationError):
        tools['recon_note'].params_model(target='example.com', action='create', path='../secrets')
    with pytest.raises(ValidationError):
        tools['recon_note'].params_model(target='example.com', action='create', content='x' * 8001)


def test_evidence_write_failure_rolls_back_record_revision(tmp_path, monkeypatch):
    tools = workspace(tmp_path)
    first = invoke(tools['recon_note'], target='example.com', action='create', title='A', content='before')
    original = EvidenceStore.put
    # Fault injection must stay in this process; run_sync normally creates a fresh worker.
    async def local_call(function, *args, **kwargs):
        return function(*args, **kwargs)
    monkeypatch.setattr('platforms.sync_worker.run_sync', local_call)
    def fail(*args, **kwargs):
        raise OSError('unavailable')
    monkeypatch.setattr(EvidenceStore, 'put', fail)
    assert not invoke(tools['recon_note'], target='example.com', action='update', record_id=first.data['record']['id'], content='after').success
    monkeypatch.setattr(EvidenceStore, 'put', original)
    record = invoke(tools['recon_note'], target='example.com', action='get', record_id=first.data['record']['id']).data['record']
    assert record['content'] == 'before' and record['revision'] == 1
