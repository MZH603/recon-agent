"""Recon-native notes, coverage, threat models and evidence-bound findings."""
from __future__ import annotations

from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tools.base import BaseTool, ToolResult


class WorkspaceConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    enabled: bool = True
    directory: str = ''
    max_records: int = Field(default=100, ge=1, le=100)


class RecordParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=2048)
    action: Literal['create', 'get', 'list', 'update', 'delete'] = 'list'
    record_id: str | None = Field(default=None, pattern=r'^[0-9a-f]{32}$')
    limit: int = Field(default=50, ge=1, le=100)


class NoteParams(RecordParams):
    title: str = Field(default='', max_length=256)
    content: str = Field(default='', max_length=8000)
    category: Literal['general', 'findings', 'methodology', 'questions', 'plan'] = 'general'


class EvidenceParams(RecordParams):
    evidence_ids: list[str] = Field(default_factory=list, max_length=16)

    @field_validator('evidence_ids')
    @classmethod
    def validate_ids(cls, values):
        import re
        if any(not re.fullmatch(r'[0-9a-f]{64}', item) for item in values):
            raise ValueError('evidence IDs must be SHA256 identifiers')
        return list(dict.fromkeys(values))

class CoverageParams(EvidenceParams):
    surface: str = Field(default='', max_length=512)
    risk_area: str = Field(default='', max_length=256)
    outcome: Literal['not_tested', 'observed', 'verified', 'inconclusive', 'not_applicable'] = 'not_tested'
    content: str = Field(default='', max_length=8000)


class ThreatModelParams(RecordParams):
    title: str = Field(default='', max_length=256)
    content: str = Field(default='', max_length=8000)


class FindingParams(EvidenceParams):
    title: str = Field(default='', max_length=256)
    content: str = Field(default='', max_length=8000)
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = 'info'
    status: Literal['candidate', 'observed', 'verified'] = 'candidate'


class SnapshotParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=2048)


class WorkspaceTool(BaseTool):
    cacheable = False
    deferred = True
    min_level = 0

    def __init__(self, store, name, description, collection, params_model):
        self.store = store
        self.name = name
        self.description = description
        self.collection = collection
        self.params_model = params_model

    async def run(self, params):
        from platforms.sync_worker import run_sync
        fields = params.model_dump(exclude={'target', 'action', 'record_id', 'limit'})
        action = getattr(params, 'action', 'snapshot')
        if action == 'update':
            fields = {key: value for key, value in fields.items() if key in params.model_fields_set}
        try:
            self.store.used = True
            data, record = await run_sync(self.store.operate, params.target, self.collection, action,
                getattr(params, 'record_id', None), fields, getattr(params, 'limit', 50))
            return ToolResult(name=self.name, success=True, data=data,
                evidence=[f"local:{record['evidence_id']}"], source_hash=record['sha256'],
                artifacts=[{'kind': 'workspace_snapshot', 'evidence_id': record['evidence_id'],
                    'path': str((self.store.evidence.root / (record['evidence_id'] + '.json')).resolve())}],
                summary=f'{self.name}: {action} · 当前会话记录快照')
        except Exception:
            return ToolResult.err(self.name, 'Workspace operation rejected: missing record, invalid fields/evidence or unavailable storage')


def build_workspace_tools(settings, session_id=None):
    config = settings.extension_tools.workspace
    if not config.enabled:
        return []
    from tools.runtime.evidence_store import evidence_store_for
    from tools.runtime.workspace_store import WorkspaceStore
    store = WorkspaceStore(config, evidence_store_for(settings), session_id or uuid4().hex)
    return [
        WorkspaceTool(store, 'recon_note', '当前目标/会话笔记：创建、修订、查询、删除', 'notes', NoteParams),
        WorkspaceTool(store, 'recon_coverage', '记录覆盖面与未测试项；verified 必须引用本地证据', 'coverage', CoverageParams),
        WorkspaceTool(store, 'recon_threat_model', '当前目标/会话的威胁模型记录', 'threat_models', ThreatModelParams),
        WorkspaceTool(store, 'recon_finding', '有同目标证据的发现记录；候选、观测、验证声明分别保存', 'findings', FindingParams),
        WorkspaceTool(store, 'workspace_snapshot', '读取当前目标/会话最新笔记、覆盖面、威胁模型和发现', None, SnapshotParams),
    ]
