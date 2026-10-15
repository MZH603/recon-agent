"""Tool integration configurations (adapted from original imports)."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CustomToolConfig(BaseModel):
    """Configuration for a custom command-line tool."""
    model_config = ConfigDict(validate_assignment=True)
    
    name: str = Field(..., description="Tool name identifier")
    kind: str = Field(..., description="Tool type: command, http, etc.")
    command: Optional[list[str]] = Field(default=None, description="Command to execute")
    url: Optional[str] = Field(default=None, description="HTTP URL if kind=http")
    method: Optional[str] = Field(default="GET", description="HTTP method")
    timeout_seconds: int = Field(default=60, ge=1, le=300, description="Timeout in seconds")
    max_output_bytes: int = Field(default=16000, ge=1024, description="Max output bytes")
    scan_level: int = Field(default=0, ge=0, le=2, description="Scan level requirement")
    input_schema: Optional[dict] = Field(default=None, description="JSON schema for inputs")
    response_format: str = Field(default="text", description="Response format")
    
    @field_validator("timeout_seconds")
    @classmethod
    def timeout_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError("timeout_seconds must be positive")
        return v


class MCPServerConfig(BaseModel):
    """Configuration for an MCP server."""
    model_config = ConfigDict(validate_assignment=True)
    
    name: str = Field(..., description="Server name")
    transport: str = Field(..., description="Transport type: stdio, sse, etc.")
    command: str = Field(..., description="Command to start server")
    allowed_tools: list[str] = Field(default_factory=list, description="Allowed tool names")
    enabled: bool = Field(default=True, description="Whether server is enabled")
