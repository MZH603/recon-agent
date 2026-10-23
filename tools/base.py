"""工具基类与结果契约（HARD：ToolResult 必须携带 evidence + source_hash，降级必须标注）。"""
from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field, model_validator
from typing import Literal


class ToolResult(BaseModel):
    """统一工具结果（跨平台、跨工具一致的结构化契约）。"""

    name: str
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    data: dict = Field(default_factory=dict)   # 结构化结果（模板压缩后注入上下文）
    evidence: list[str] = Field(default_factory=list)  # HARD: 来源清单
    source_hash: str = ""                      # HARD: 响应体 SHA256 前 64 字节
    confidence: float = 1.0                    # 置信度（降级自动下调一档）
    degraded: bool = False                     # HARD: 是否降级模式
    error: str = ""
    status: Literal['success', 'partial', 'failure', 'timeout', 'cancelled'] = 'success'
    summary: str = ''
    artifacts: list[dict] = Field(default_factory=list)
    error_code: str = ''
    elapsed_seconds: float = 0
    timeout_seconds: float = 0
    cancellation_status: str = ''
    outcome_unknown: bool = False
    raw_artifact_id: str = ''
    artifact_error: str = ''
    execution_id: str = ''
    started_at: str = ''

    @model_validator(mode='before')
    @classmethod
    def legacy_status(cls, value):
        if isinstance(value, dict) and 'status' not in value:
            value = dict(value)
            value['status'] = 'success' if value.get('success') else 'failure'
        return value

    @classmethod
    def err(cls, name: str, msg: str) -> "ToolResult":
        """显式失败（HARD：异常转错误结果，不静默、不编造）。"""
        return cls(name=name, success=False, error=msg, exit_code=1)


class BaseTool(ABC):
    """工具抽象：Schema 契约 + 风险级别 + 最低扫描深度（门控依据）。"""

    name: str = ""
    description: str = ""
    risk_level: str = "低"   # 低 | 中 | 高
    min_level: int = 0       # HARD: 0=L0 被动可用；1=L1；2=L2（三级门控）
    cacheable: bool = True  # Completed signature reuse is unsafe for stateful connectors.
    remote_execution: bool = False  # Local cancellation cannot prove remote work stopped.
    params_model: type[BaseModel]

    def brief(self) -> str:
        """渐进式披露用的一行简介（HARD：先给名称+一句话，选定后再注入完整 Schema）。"""
        return f"{self.name} — {self.description}（风险:{self.risk_level}/最低级别:L{self.min_level}）"

    def to_openai_spec(self) -> dict:
        """导出原生 Tool Use 的 function spec（Pydantic Schema → JSON Schema）。"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": f"{self.description}【风险:{self.risk_level}/最低级别:L{self.min_level}】",
                "parameters": self.params_model.model_json_schema(),
            },
        }

    @abstractmethod
    async def run(self, params: BaseModel) -> ToolResult:
        """执行工具；所有异常必须收敛为 ToolResult.err，不向上抛。"""
