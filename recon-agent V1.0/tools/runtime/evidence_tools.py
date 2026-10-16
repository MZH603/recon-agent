"""Passive, scope-bound local evidence readers."""
from pydantic import BaseModel,ConfigDict,Field
from tools.base import BaseTool,ToolResult
from tools.runtime.evidence_store import canonical_json,evidence_store_for


class EvidenceSearchParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    query: str=Field(default='',max_length=256)
    limit: int=Field(default=10,ge=1,le=100)


class EvidenceGetParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    evidence_id: str=Field(pattern=r'^[0-9a-f]{64}$')
    max_bytes: int=Field(default=20000,ge=1,le=100000)
    offset: int=Field(default=0,ge=0)


class EvidenceSearchTool(BaseTool):
    cacheable=False
    name='evidence_search'
    description='搜索当前授权目标的本地证据元数据'
    min_level=0
    params_model=EvidenceSearchParams
    def __init__(self,settings): self.store=evidence_store_for(settings)
    async def run(self,params):
        try:
            rows=self.store.search(params.target,params.query,params.limit)
            return ToolResult(name=self.name,success=True,data={'evidence':rows},evidence=[f'local:{row["evidence_id"]}' for row in rows])
        except (OSError,ValueError,KeyError) as exc: return ToolResult.err(self.name,str(exc))


class EvidenceGetTool(BaseTool):
    name='evidence_get'
    description='按证据 ID 读取当前目标的本地原始记录（有字节上限）'
    min_level=0
    params_model=EvidenceGetParams
    def __init__(self,settings): self.store=evidence_store_for(settings)
    async def run(self,params):
        try:
            record=self.store.get(params.evidence_id,target=params.target)
            raw=canonical_json(record['payload']); truncated=len(raw)>params.max_bytes or params.offset>0
            if params.offset>len(raw): raise ValueError('offset exceeds evidence size')
            if params.offset<len(raw) and raw[params.offset] & 0xc0 == 0x80:
                raise ValueError('offset must be a UTF-8 character boundary')
            part=raw[params.offset:params.offset+params.max_bytes]
            page=part.decode('utf-8',errors='ignore')
            if part and not page:
                raise ValueError('max_bytes too small for next character')
            data={key:value for key,value in record.items() if key!='payload'}
            end=params.offset+len(page.encode('utf-8'))
            data.update({'truncated':truncated,'payload_preview':page,'offset':params.offset,'next_offset':end,'has_more':end<len(raw)})
            if not truncated: data['payload']=record['payload']
            return ToolResult(name=self.name,success=True,data=data,evidence=[f'local:{params.evidence_id}'],source_hash=record['sha256'],degraded=truncated)
        except (OSError,ValueError,KeyError) as exc: return ToolResult.err(self.name,str(exc))


class ArtifactReadParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    artifact_id: str=Field(pattern=r'^[0-9a-f]{64}$')
    offset: int=Field(default=0,ge=0)
    max_bytes: int=Field(default=4000,ge=4,le=8000)


class ArtifactReadTool(BaseTool):
    name='artifact_read'
    description='按产物 ID 和字节偏移分页读取当前目标完整工具结果'
    min_level=0
    cacheable=False
    params_model=ArtifactReadParams
    def __init__(self,settings):
        from tools.runtime.result_payload import ResultPayloads
        self.payloads=ResultPayloads(settings)
        self.maximum=max(4,min(8000,self.payloads.limit//3))
    async def run(self,params):
        try:
            from platforms.sync_worker import run_sync
            data=await run_sync(self.payloads.read,params.artifact_id,params.target,params.offset,min(params.max_bytes,self.maximum))
            return ToolResult(name=self.name,success=True,summary='完整产物分页',data=data,evidence=[f'artifact:{params.artifact_id}'])
        except (OSError,ValueError,KeyError) as exc:
            return ToolResult.err(self.name,str(exc))


def build_evidence_tools(settings): return [EvidenceSearchTool(settings),EvidenceGetTool(settings),ArtifactReadTool(settings)]
