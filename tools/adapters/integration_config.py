"""Validated, operator-owned integration definitions; arguments never contain code."""
from __future__ import annotations

import string
from typing import Any, Literal
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, model_validator


CUSTOM_PROTECTED_ARGUMENTS = {'target','arguments','code','command','script','url','min_level','scan_level','LAB_MODE','GATE_PER_STEP_CONFIRM'}


def _local_schema_references(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if key in ('$ref','$dynamicRef') and (not isinstance(item,str) or not item.startswith('#')):
                raise ValueError('external input schema references are forbidden')
            _local_schema_references(item)
    elif isinstance(value,list):
        for item in value: _local_schema_references(item)


class CustomToolConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(pattern=r'^[A-Za-z][A-Za-z0-9_]{0,63}$')
    kind: Literal['command','script','http','shell']
    description: str = ''
    enabled: bool = True
    min_level: int | None = Field(default=None,ge=0,le=2)
    input_schema: dict[str,Any] = Field(default_factory=lambda:{'type':'object','properties':{},'additionalProperties':False})
    command: list[str] = Field(default_factory=list)
    script: str = ''
    url: str = ''
    method: Literal['GET','HEAD'] = 'GET'
    env: dict[str,str] = Field(default_factory=dict)
    headers_env: dict[str,str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=30,ge=1,le=120)
    max_output_bytes: int = Field(default=200000,ge=1,le=2097152)
    response_format: Literal['text','json','jsonl'] = 'text'
    deferred: bool = True

    @model_validator(mode='after')
    def validate_definition(self):
        minimum={'command':2,'script':2,'http':1,'shell':0}[self.kind]
        if self.min_level is None: self.min_level=minimum
        if self.min_level<minimum: raise ValueError('min_level below required safety level')
        _local_schema_references(self.input_schema)
        try:
            Draft202012Validator.check_schema(self.input_schema)
        except SchemaError:
            raise ValueError("invalid input JSON schema") from None
        if self.input_schema.get('type')!='object': raise ValueError('input_schema must describe an object')
        properties=self.input_schema.get('properties',{})
        reserved=CUSTOM_PROTECTED_ARGUMENTS
        if reserved.intersection(properties): raise ValueError('protected arguments cannot be configured')
        allowed={'target',*properties}
        for value in [*self.command,self.url]:
            for _,field,spec,conversion in string.Formatter().parse(value):
                if field is not None and (field not in allowed or spec or conversion):
                    raise ValueError('only declared scalar placeholders are allowed')
        if self.kind in ('command','shell') and not self.command: raise ValueError('command argv required')
        if self.kind=='script' and not self.script.strip(): raise ValueError('script required')
        if self.kind=='http':
            parts=urlsplit(self.url)
            if parts.scheme not in ('http','https') or not parts.netloc or parts.username or parts.password:
                raise ValueError('HTTP URL must be http(s) without credentials')
        for mapping in (self.env,self.headers_env):
            if any(not key or not source for key,source in mapping.items()): raise ValueError('environment mapping must have names')
        return self


class MCPServerConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(pattern=r'^[A-Za-z][A-Za-z0-9_]{0,63}$')
    enabled: bool = False
    transport: Literal['stdio','http','sse'] = 'stdio'
    command: str = ''
    args: list[str] = Field(default_factory=list)
    url: str = ''
    env: dict[str,str] = Field(default_factory=dict)
    headers_env: dict[str,str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=30,ge=1,le=120)
    max_output_bytes: int = Field(default=200000,ge=1,le=2097152)
    min_level: int = Field(default=2,ge=2,le=2)
    allowed_tools: list[str] = Field(default_factory=list)
    target_fields: dict[str,list[str]] = Field(default_factory=dict)
    deferred: bool = True

    @model_validator(mode='after')
    def validate_definition(self):
        if self.transport=='stdio' and not self.command: raise ValueError('stdio command required')
        if self.transport!='stdio':
            parts=urlsplit(self.url)
            if parts.scheme not in ('http','https') or not parts.netloc or parts.username or parts.password:
                raise ValueError('MCP HTTP URL must be http(s) without credentials')
        if any(tool not in self.target_fields for tool in self.allowed_tools):
            raise ValueError('every allowed tool requires explicit target_fields')
        if len(set(self.allowed_tools))!=len(self.allowed_tools): raise ValueError('duplicate allowed tools')
        return self
