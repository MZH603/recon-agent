"""Offline tool catalog; deferred schemas are selected without granting permission."""
from pydantic import BaseModel, ConfigDict, Field
from tools.base import BaseTool, ToolResult


class CatalogParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str
    query: str = Field(default='', max_length=200)
    select: list[str] = Field(default_factory=list, max_length=32)
    limit: int = Field(default=20, ge=1, le=50)


class ToolCatalogTool(BaseTool):
    name = 'tool_catalog'
    cacheable = False
    description = '搜索工具目录；select 指定工具名以披露自定义工具或 MCP 的完整参数 Schema，授权门控仍生效'
    params_model = CatalogParams
    def __init__(self, registry):
        self.registry = registry

    async def run(self, params):
        unknown = [name for name in params.select if self.registry.get(name) is None]
        if unknown:
            return ToolResult.err(self.name, 'Unknown tools: ' + ', '.join(unknown))
        self.registry.select_tools(self.registry.selected_tool_names + params.select)
        query = params.query.casefold()
        matches = [tool for name in self.registry.names()
                   if (tool := self.registry.get(name)) and query in tool.brief().casefold()]
        return ToolResult(name=self.name, success=True, data={
            'tools': [{'name': t.name, 'description': t.description, 'min_level': t.min_level,
                       'deferred': getattr(t, 'deferred', False), 'cacheable': t.cacheable} for t in matches[:params.limit]],
            'total': len(matches), 'selected_tools': self.registry.selected_tool_names})
