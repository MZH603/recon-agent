"""Extension tools configuration."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ExtensionToolsConfig(BaseModel):
    """Configuration for optional extension tools."""
    model_config = ConfigDict(validate_assignment=True)
    
    enabled: bool = Field(default=False, description="Whether extension tools are enabled")
    tool_dirs: list[str] = Field(default_factory=list, description="Extension tool directory paths")
