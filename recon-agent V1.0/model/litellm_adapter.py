"""LiteLLM 统一适配器（HARD：唯一允许接触具体 SDK 的地方；tool_call 差异在此归一化）。"""
from __future__ import annotations

import asyncio
import json
import os
from model.cost import response_cost
from typing import Any

from model.base import (
    LLMProvider,
    LLMResponse,
    ModelUnavailable,
    NormalizedToolCall,
)


def _import_litellm() -> Any:
    """惰性导入 litellm：离线/未安装时其余功能照常运行（分层降级）。"""
    try:
        import litellm
        return litellm
    except ImportError as exc:
        raise ModelUnavailable("litellm 未安装（pip install litellm），无法调用模型") from exc


class LiteLLMAdapter(LLMProvider):
    """通过 litellm.acompletion 统一路由所有主流模型。

    - temperature=0（HARD：结构化任务确定性）；
    - 超时 + 指数退避重试；
    - 不可达抛 ModelUnavailable → 上层 fallback 链 → 耗尽则离线模板报告。
    """

    def __init__(
        self,
        model: str,
        api_base: str | None = None,
        api_key_env: str | None = None,
        temperature: int = 0,
        max_retries: int = 2,
        timeout: int = 120,
    ) -> None:
        self.model = model
        self.api_base = api_base
        self.api_key_env = api_key_env
        self.temperature = temperature
        self.max_retries = max_retries
        self.timeout = timeout

    async def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        """调用模型并归一化响应（重试耗尽抛 ModelUnavailable）。"""
        litellm = _import_litellm()
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,  # HARD
            "timeout": self.timeout,
            "num_retries": 0,  # 重试由本层显式控制（指数退避）
        }
        if self.api_key_env:
            api_key = os.environ.get(self.api_key_env)
            if not api_key:
                raise ModelUnavailable("配置的 API Key 环境变量未设置")
            kwargs["api_key"] = api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await litellm.acompletion(**kwargs)
                return self._to_response(resp, litellm)
            except ModelUnavailable:
                raise
            except Exception as exc:  # noqa: BLE001 —— 统一收敛为 ModelUnavailable
                last_error = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
        raise ModelUnavailable(
            f"模型 {self.model} 不可达（重试 {self.max_retries} 次后放弃）: {type(last_error).__name__}"
        )

    def _to_response(self, resp: Any, sdk: Any = None) -> LLMResponse:
        """把 litellm 响应收敛为 LLMResponse（各模型差异在此抹平）。"""
        message = resp.choices[0].message
        usage = getattr(resp, "usage", None)
        cost = response_cost(resp, sdk)
        return LLMResponse(
            content=message.content or "",
            tool_calls=self._normalize_tool_calls(getattr(message, "tool_calls", None)),
            token_usage={
                "input": getattr(usage, "prompt_tokens", 0) or 0,
                "output": getattr(usage, "completion_tokens", 0) or 0,
                "cost": cost, "cost_known": cost is not None,
            },
            model=getattr(resp, "model", "") or self.model,
        )

    def _normalize_tool_calls(self, raw: Any) -> list[NormalizedToolCall]:
        """OpenAI/Anthropic/Google 的 tool_call → NormalizedToolCall（HARD：归一化唯一入口）。"""
        calls: list[NormalizedToolCall] = []
        if not raw:
            return calls
        for index, tc in enumerate(raw):
            function = getattr(tc, "function", None)
            if function is None:
                continue
            args_raw = getattr(function, "arguments", "{}") or "{}"
            try:
                arguments = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except json.JSONDecodeError:
                arguments = {}  # 显式交给上层校验报错回填，而非猜测
            calls.append(NormalizedToolCall(
                id=getattr(tc, "id", None) or f"call-{index}",
                name=getattr(function, "name", "") or "",
                arguments=arguments,
            ))
        return calls

    def count_tokens(self, text: str) -> int:
        """轻量粗估（len/4），避免额外依赖；预算控制精度足够。"""
        return max(1, len(text or "") // 4)
