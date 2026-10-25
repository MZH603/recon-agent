"""builtin 数据源查询工具（L0 被动：外部威胁情报 API 聚合查询）。
支持：FOFA、Quake、ZoomEye、微步在线、ThreatBook、Shodan、Censys、BinaryEdge。
"""
from __future__ import annotations

import asyncio
from pydantic import BaseModel, Field
from typing import Optional

from tools.base import BaseTool, ToolResult
from tools.adapters.datasources import query_all_sources, ADAPTERS
from utils.config import Settings, get_settings


class DataSourceQueryParams(BaseModel):
    """数据源查询参数。"""
    target: str = Field(..., description="查询目标：域名/IP/CIDR/关键词")
    sources: list[str] = Field(
        default_factory=lambda: ["fofa", "quake", "zoomeye"],
        description="启用的数据源列表"
    )
    page: int = Field(1, ge=1, le=100)
    size: int = Field(100, ge=1, le=1000)


class DataSourceQueryTool(BaseTool):
    """外部威胁情报数据源聚合查询（L0 被动）。"""

    name = "datasource_query"
    description = "聚合查询多个外部威胁情报平台：FOFA/Quake/ZoomEye/微步/ThreatBook/Shodan/Censys/BinaryEdge（被动 L0）"
    risk_level = "低"
    min_level = 0
    params_model = DataSourceQueryParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, DataSourceQueryParams)

        # Validate sources
        valid_sources = [s for s in params.sources if s.lower() in ADAPTERS]
        invalid = set(params.sources) - set(valid_sources)
        if invalid:
            return ToolResult.err(self.name, f"未知数据源: {', '.join(invalid)}")

        # Get API keys from settings
        api_keys = {}
        api_secrets = {}
        for source in valid_sources:
            key_attr = f"{source.upper()}_API_KEY"
            secret_attr = f"{source.upper()}_API_SECRET"
            if hasattr(self._settings, key_attr):
                key = getattr(self._settings, key_attr, "")
                if key:
                    api_keys[source] = key
            if hasattr(self._settings, secret_attr):
                secret = getattr(self._settings, secret_attr, "")
                if secret:
                    api_secrets[source] = secret

        if not api_keys:
            return ToolResult.err(self.name, "未配置任何数据源 API Key，请在配置文件中设置")

        # Query all sources
        results = await query_all_sources(
            query=params.target,
            settings=self._settings,
            enabled_sources=valid_sources,
            api_keys=api_keys,
            api_secrets=api_secrets
        )

        # Aggregate assets
        all_assets = []
        errors = []
        for result in results:
            if result.success:
                all_assets.extend(result.assets)
            else:
                errors.append(f"{result.source}: {result.error}")

        evidence = [f"数据源查询: {params.target}, 来源: {len(valid_sources)} 个"]
        if errors:
            evidence.append(f"错误: {'; '.join(errors)}")

        return ToolResult(
            name=self.name,
            success=len(all_assets) > 0 or len(errors) < len(valid_sources),
            data={
                "target": params.target,
                "sources_queried": valid_sources,
                "assets": all_assets,
                "total_assets": len(all_assets),
                "errors": errors
            },
            evidence=evidence,
            source_hash="",
            confidence=0.8 if all_assets else 0.3
        )