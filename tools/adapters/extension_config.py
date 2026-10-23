"""Optional native tools; connector/process creation stays disabled by default."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tools.adapters.proxy import CaidoConfig
from tools.adapters.scanners import ScannerConfig
from tools.adapters.search import SearchConfig
from tools.runtime.workspace import WorkspaceConfig


class ExtensionToolsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    scanners: list[ScannerConfig] = Field(default_factory=list, max_length=5)
    search: SearchConfig | None = None
    caido: CaidoConfig | None = None
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    knowledge_enabled: bool = True

    @model_validator(mode="after")
    def unique_scanners(self):
        if len({item.kind for item in self.scanners}) != len(self.scanners):
            raise ValueError("duplicate scanner kind")
        return self
