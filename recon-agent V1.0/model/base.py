"""模型接入抽象（HARD：业务代码只依赖本层接口，禁止直接 import openai/anthropic 等 SDK）。"""
from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Any, Callable

from pydantic import BaseModel, Field


class ModelUnavailable(RuntimeError):
    """模型不可达 / 未配置 / 调用耗尽（上层捕获后降级到模板报告）。"""


class PartialStreamError(ModelUnavailable):
    """A response started; retrying or switching providers would mix responses."""


@dataclass(frozen=True)
class StreamEvent:
    """Process-local observation, never a tool execution or persisted decision."""
    kind: str
    content: str = ''
    index: int = 0
    name: str = ''
    arguments: str = ''
    token_usage: dict = field(default_factory=dict)


def observe(callback: Callable | None, event: Any) -> None:
    """A broken display must not change execution; cancellation still propagates."""
    if callback is not None:
        try:
            callback(event)
        except Exception:
            pass


def response_events(response: 'LLMResponse', callback: Callable | None) -> None:
    if response.reasoning_content:
        observe(callback, StreamEvent('reasoning', content=response.reasoning_content))
    if response.content:
        observe(callback, StreamEvent('content', content=response.content))
    for index, call in enumerate(response.tool_calls):
        observe(callback, StreamEvent('tool', index=index, name=call.name,
                                     arguments=json.dumps(call.arguments, ensure_ascii=False)))


class StreamUsage:
    """Track partial consumption independently of display success or cancellation."""
    def __init__(self):
        self.started = False
        self.output = ''
        self.usage = {}

    def add(self, event: StreamEvent):
        if event.kind in ('chunk', 'content', 'tool', 'usage', 'reasoning'):
            self.started = True
        self.output += event.content + event.arguments
        if event.token_usage:
            self.usage.update(event.token_usage)

    def partial(self, messages, count_tokens, tools=None):
        from model.cost import valid_cost
        request = json.dumps(messages, ensure_ascii=False) + (json.dumps(tools, ensure_ascii=False) if tools else '')
        actual = {key: self.usage.get(key) for key in ('input', 'output')}
        known = {key: isinstance(value, int) and not isinstance(value, bool) and value >= 0
                 for key, value in actual.items()}
        cost = valid_cost(self.usage.get('cost'))
        return {'input': actual['input'] if known['input'] else conservative_tokens(request, count_tokens),
                'output': actual['output'] if known['output'] else conservative_tokens(self.output, count_tokens),
                'cost': cost, 'cost_known': cost is not None,
                'estimated': not all(known.values()) or bool(self.usage.get('estimated'))}


def estimate_text_tokens(text: str) -> int:
    """Lightweight fallback: wide characters count individually, Latin about four per token."""
    import math
    import unicodedata
    text = text or ''
    wide = sum(unicodedata.east_asian_width(char) in ('W', 'F') for char in text)
    return max(1, wide + math.ceil((len(text) - wide) / 4))


def conservative_tokens(text: str, count_tokens: Callable) -> int:
    """Prefer the model counter; unknown usage is an estimate, never a byte count."""
    try:
        value = count_tokens(text)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    except Exception:
        pass
    return estimate_text_tokens(text)


class NormalizedToolCall(BaseModel):
    """各模型 tool_call 归一化后的统一结构（HARD：业务代码只消费此结构）。"""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class LLMResponse(BaseModel):
    """统一 LLM 响应。"""

    content: str = ""
    reasoning_content: str = ""  # Provider protocol history, never a user-facing answer.
    tool_calls: list[NormalizedToolCall] = Field(default_factory=list)
    token_usage: dict = Field(default_factory=dict)
    model: str = ""


class LLMProvider(ABC):
    """模型提供者抽象：complete + count_tokens（模型无关的两大能力）。"""

    @abstractmethod
    async def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        """发送对话，返回归一化响应。"""

    async def complete_stream(self, messages: list[dict], tools: list[dict] | None = None,
                              on_delta: Callable | None = None) -> LLMResponse:
        """Compatible extension: providers implementing only complete remain valid."""
        response = await self.complete(messages, tools)
        response_events(response, on_delta)
        return response

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
