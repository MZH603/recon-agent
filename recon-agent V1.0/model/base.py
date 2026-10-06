"""模型接入抽象（HARD：业务代码只依赖本层接口，禁止直接 import openai/anthropic 等 SDK）。"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class ModelUnavailable(RuntimeError):
    """模型不可达 / 未配置 / 调用耗尽（上层捕获后降级到模板报告）。"""


class NormalizedToolCall(BaseModel):
    """各模型 tool_call 归一化后的统一结构（HARD：业务代码只消费此结构）。"""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    """统一 LLM 响应。"""

    content: str = ""
    tool_calls: list[NormalizedToolCall] = Field(default_factory=list)
    token_usage: dict = Field(default_factory=lambda: {"input": 0, "output": 0})
    model: str = ""


class LLMProvider(ABC):
    """模型提供者抽象：complete + count_tokens（模型无关的两大能力）。"""

    @abstractmethod
    async def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        """发送对话，返回归一化响应。"""

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """粗估 token 数（预算控制用）。"""


def parse_xml_tool_calls(text: str) -> list[NormalizedToolCall]:
    """解析 System Prompt 约定的 <tool_call> XML 协议。

    用途：兼容不支持原生 Tool Use 的模型/端点——系统提示词声明了该协议，
    Agent 层对"原生 tool_calls 为空"的响应做 XML 兜底解析（显式失败，不猜测）。

    安全说明（bandit B314 决策）：输入源为本会话 LLM 输出（长度受上下文预算约束）、
    解析失败显式捕获、现代 CPython expat 内置 billion-laughs 缓解——
    故不引入 defusedxml 新依赖（HARD：核心依赖 ≤5）。
    """
    calls: list[NormalizedToolCall] = []
    for index, block in enumerate(re.findall(r"<tool_call>(.*?)</tool_call>", text, re.S)):
        try:
            node = ET.fromstring(f"<root>{block}</root>")
        except ET.ParseError:
            continue
        name = (node.findtext("tool_name") or "").strip()
        if not name:
            continue
        params: dict[str, str] = {}
        pnode = node.find("parameters")
        if pnode is not None:
            for child in pnode:
                params[child.tag] = (child.text or "").strip()
        purpose = (node.findtext("purpose") or "").strip()
        risk = (node.findtext("risk_level") or "低").strip()
        calls.append(NormalizedToolCall(
            id=f"xml-{index}",
            name=name,
            arguments={**params, "_purpose": purpose, "_risk_level": risk},
        ))
    return calls
