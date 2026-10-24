"""Stable public contract for tool providers."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from pydantic import BaseModel


API_VERSION = '1.0'


@dataclass(frozen=True)
class PluginManifest:
    id: str
    version: str
    api_version: str
    capabilities: tuple[str, ...]
    config_model: type[BaseModel] | None = None
    dependencies: tuple[str, ...] = ()

    def __post_init__(self):
        if not re.fullmatch(r'[a-z][a-z0-9_-]*', self.id):
            raise ValueError(f'Invalid plugin ID: {self.id}')
        if not self.version or not self.api_version:
            raise ValueError('Plugin version and API version are required')
        if self.api_version.split('.')[0] != API_VERSION.split('.')[0]:
            raise ValueError(f'Incompatible plugin API version: {self.api_version}')
        if not self.capabilities or any(not isinstance(cap, str) or not cap for cap in self.capabilities):
            raise ValueError('Plugin capabilities are required')
        if self.config_model is not None and not issubclass(self.config_model, BaseModel):
            raise ValueError('Plugin config_model must be a Pydantic model')
        if self.id in self.dependencies or len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError(f'Invalid dependencies for {self.id}')


class ToolProvider(Protocol):
    """register declares tools without starting external work; start owns runtime I/O."""
    manifest: PluginManifest

    def describe_tool_names(self, validated_config: BaseModel | dict) -> tuple[str, ...]: ...
    def register(self, host, validated_config: BaseModel | dict) -> None: ...
    async def start(self, session_view) -> None: ...
    async def close(self) -> None: ...
