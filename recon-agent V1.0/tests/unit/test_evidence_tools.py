import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from tools.evidence_store import EvidenceStore
from tools.evidence_tools import build_evidence_tools


def test_evidence_immutable_complete_hash_and_scope(tmp_path):
    store=EvidenceStore(tmp_path)
    payload={'endpoints':[{'path':f'/api/{n}'} for n in range(1000)]}
    evidence_id=store.put('example.com','api_recon',payload)
    assert store.put('example.com','api_recon',payload)==evidence_id
    record=store.get(evidence_id,target='https://example.com/path')
    assert record['payload']==payload and len(record['sha256'])==64
    raw=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    assert record['sha256']==hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError,match='scope'): store.get(evidence_id,target='other.com')
    rows=store.search('example.com',query='/api/999')
    assert len(rows)==1 and 'payload' not in rows[0]
    assert not store.search('other.com')


def test_evidence_rejects_paths_tamper_and_oversized_payload(tmp_path):
    store=EvidenceStore(tmp_path)
    for bad in ['../private','/absolute','x'*64,'a'*63]:
        with pytest.raises((ValueError,FileNotFoundError)): store.get(bad)
    with pytest.raises(ValueError,match='limit'): store.put('example.com','large',{'raw':'x'*2097153})
    evidence_id=store.put('example.com','test',{'safe':1})
    path=tmp_path/(evidence_id+'.json'); record=json.loads(path.read_text()); record['payload']={'safe':2}; path.write_text(json.dumps(record))
    with pytest.raises(ValueError,match='hash'): store.get(evidence_id)


def test_evidence_tools_target_required_and_bounded(tmp_path):
    store=EvidenceStore(tmp_path); evidence_id=store.put('example.com','fixture',{'raw':'x'*100000})
    tools={tool.name:tool for tool in build_evidence_tools(SimpleNamespace(TOOL_EVIDENCE_DIR=str(tmp_path)))}
    assert set(tools)=={'evidence_get','evidence_search','artifact_read'}
    for tool in tools.values():
        assert tool.min_level==0
        assert 'target' in tool.params_model.model_json_schema()['required']
    getter=tools['evidence_get']; params=getter.params_model(target='example.com',evidence_id=evidence_id,max_bytes=1024)
    result=asyncio.run(getter.run(params))
    assert result.success and result.data['truncated'] and len(result.data['payload_preview'].encode())<=1024
    result=asyncio.run(getter.run(getter.params_model(target='elsewhere.com',evidence_id=evidence_id)))
    assert not result.success
    chinese=store.put('example.com','fixture',{'raw':'中文'})
    for offset in (8,9):
        result=asyncio.run(getter.run(getter.params_model(target='example.com',evidence_id=chinese,max_bytes=1,offset=offset)))
        assert not result.success  # Never return an empty successful page without progress.
