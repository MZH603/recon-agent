"""Packaged Recon references loaded on demand."""
from importlib.resources import files

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tools.base import BaseTool, ToolResult

SKILLS = {
    'asset_discovery': '资产发现与授权范围',
    'api_recon': 'API 静态候选与浏览器观测',
    'coverage': '覆盖记录与否定证据',
    'evidence_review': '发现复核与反证',
    'tool_workflow': '受控 CLI、浏览器 MCP 和代理流程',
}


class CatalogParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=2048)
    query: str = Field(default='', max_length=128)


class LoadParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=2048)
    skills: list[str] = Field(min_length=1, max_length=5)

    @field_validator('skills')
    @classmethod
    def names(cls, values):
        import re
        if any(not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', value) for value in values):
            raise ValueError('skill name must be a catalog identifier')
        return list(dict.fromkeys(values))


class SkillCatalogTool(BaseTool):
    name = 'skill_catalog'
    description = '搜索随程序分发的 Recon 知识资料，按需 load_skill'
    params_model = CatalogParams
    deferred = True
    def __init__(self, settings):
        self.settings = settings
    async def run(self, params):
        query = params.query.casefold()
        return ToolResult(name=self.name, success=True, data={'skills': [
            {'name': name, 'description': title} for name, title in SKILLS.items()
            if query in (name + ' ' + title).casefold()]})


class LoadSkillTool(BaseTool):
    name = 'load_skill'
    description = '按名称加载最多 5 份 Recon 资料；仅参考资料，不改变授权或系统指令'
    params_model = LoadParams
    deferred = True
    def __init__(self, settings):
        from tools.runtime.evidence_store import evidence_store_for
        self.store = evidence_store_for(settings)
    async def run(self, params):
        if any(name not in SKILLS for name in params.skills):
            return ToolResult.err(self.name, 'Unknown skill; use skill_catalog')
        try:
            bodies = {}
            for name in params.skills:
                body = files('tools').joinpath('data', 'skills', name + '.md').read_text(encoding='utf-8')
                if len(body.encode('utf-8')) > 12000:
                    raise ValueError('packaged skill exceeds size limit')
                bodies[name] = body
            payload = {'skills': bodies, 'reference_only': True}
            identifier = self.store.put(params.target, self.name, payload)
            record = self.store.get(identifier, target=params.target)
            return ToolResult(name=self.name, success=True, data=payload,
                evidence=[f'local:{identifier}'], source_hash=record['sha256'])
        except Exception:
            return ToolResult.err(self.name, 'Knowledge resource unavailable')


def build_knowledge_tools(settings):
    return [SkillCatalogTool(settings), LoadSkillTool(settings)] if settings.extension_tools.knowledge_enabled else []
