"""LiteLLM 统一适配器（HARD：唯一允许接触具体 SDK 的地方；tool_call 差异在此归一化）。"""
from __future__ import annotations

import asyncio
import json
import os
import inspect
from types import SimpleNamespace
from model.cost import response_cost
from typing import Any

from pydantic import SecretStr

from utils.config import optional_api_key

from model.base import (
    LLMProvider,
    LLMResponse,
    ModelUnavailable,
    NormalizedToolCall,
    StreamEvent, PartialStreamError, observe, conservative_tokens, estimate_text_tokens,
)


def _import_litellm() -> Any:
    """惰性导入 litellm：离线/未安装时其余功能照常运行（分层降级）。"""
    try:
        import litellm
        # SDK provider/pricing probes print help directly; our CLI owns diagnostics.
        # This silences SDK help without changing exceptions or pricing results.
        litellm.suppress_debug_info = True
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
        *,
        api_key: str | SecretStr | None = None,
    ) -> None:
        self.model = model
        self.api_base = api_base
        self.api_key_env = api_key_env
        self.api_key = optional_api_key(api_key)
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
        if self.api_key:
            kwargs["api_key"] = self.api_key.get_secret_value()
        elif self.api_key_env:
            api_key = os.environ.get(self.api_key_env)
            if not api_key or not api_key.strip():
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
                response = self._to_response(resp, litellm)
                usage = response.token_usage
                if usage['estimated']:
                    request = json.dumps(messages, ensure_ascii=False) + (json.dumps(tools, ensure_ascii=False) if tools else '')
                    output = response.content + response.reasoning_content + json.dumps(
                        [call.model_dump() for call in response.tool_calls], ensure_ascii=False)
                    if usage['input'] is None:
                        usage['input'] = conservative_tokens(request, self.count_tokens)
                    if usage['output'] is None:
                        usage['output'] = conservative_tokens(output, self.count_tokens)
                return response
            except ModelUnavailable as exc:
                raise ModelUnavailable(f"模型 {self.model} 不可达: {type(exc).__name__}") from None
            except Exception as exc:  # noqa: BLE001 —— 统一收敛为 ModelUnavailable
                last_error = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
        raise ModelUnavailable(
            f"模型 {self.model} 不可达（重试 {self.max_retries} 次后放弃）: {type(last_error).__name__}"
        )

    async def complete_stream(self, messages, tools=None, on_delta=None) -> LLMResponse:
        """Consume SDK deltas under one timeout per attempt; never retry partial output."""
        sdk = _import_litellm()
        kwargs = dict(model=self.model, messages=messages, temperature=self.temperature,
                      timeout=self.timeout, num_retries=0, stream=True,
                      stream_options={'include_usage': True})
        if self.api_key:
            kwargs['api_key'] = self.api_key.get_secret_value()
        elif self.api_key_env:
            key = os.environ.get(self.api_key_env, '')
            if not key.strip():
                raise ModelUnavailable('配置的 API Key 环境变量未设置')
            kwargs['api_key'] = key
        if self.api_base:
            kwargs['api_base'] = self.api_base
        if tools:
            kwargs.update(tools=tools, tool_choice='auto')
        for attempt in range(self.max_retries + 1):
            stream, started, terminated = None, False, False
            content, reasoning, calls, usage, model = [], [], {}, None, self.model
            try:
                async def consume():
                    nonlocal stream, started, terminated, usage, model
                    stream = await sdk.acompletion(**kwargs)
                    async for chunk in stream:
                        started = True
                        model = _field(chunk, 'model') or model
                        observe(on_delta, StreamEvent('chunk'))
                        chunk_usage = _field(chunk, 'usage')
                        if chunk_usage is not None:
                            usage = SimpleNamespace(prompt_tokens=_field(chunk_usage, 'prompt_tokens'),
                                                    completion_tokens=_field(chunk_usage, 'completion_tokens'))
                            observed_usage = {key: value for key, value in
                                (('input', usage.prompt_tokens), ('output', usage.completion_tokens))
                                if isinstance(value, int) and not isinstance(value, bool) and value >= 0}
                            observe(on_delta, StreamEvent('usage', token_usage=observed_usage))
                        for choice in _field(chunk, 'choices', []) or []:
                            if _field(choice, 'index', 0) != 0:
                                continue
                            reason = _field(choice, 'finish_reason')
                            if reason is not None:
                                if reason not in ('stop', 'tool_calls', 'function_call'):
                                    raise PartialStreamError('模型流未完整结束')
                                terminated = True
                            delta = _field(choice, 'delta')
                            thought = _field(delta, 'reasoning_content')
                            if isinstance(thought, str) and thought:
                                reasoning.append(thought)
                                observe(on_delta, StreamEvent('reasoning', content=thought))
                            text = _field(delta, 'content')
                            if isinstance(text, str) and text:
                                content.append(text)
                                observe(on_delta, StreamEvent('content', content=text))
                            for call in _field(delta, 'tool_calls', []) or []:
                                index = _field(call, 'index', 0)
                                entry = calls.setdefault(index, {'id': '', 'name': '', 'arguments': ''})
                                entry['id'] += _field(call, 'id') or ''
                                function = _field(call, 'function')
                                name, args = _field(function, 'name') or '', _field(function, 'arguments') or ''
                                entry['name'] += name
                                entry['arguments'] += args
                                observe(on_delta, StreamEvent('tool', index=index, name=name, arguments=args))
                    if not started:
                        raise ModelUnavailable('模型流未返回响应')
                    if not terminated:
                        raise PartialStreamError('模型流缺少结束标记，回复未完成')
                    raw_calls = [SimpleNamespace(id=value['id'], function=SimpleNamespace(
                        name=value['name'], arguments=value['arguments'])) for _, value in sorted(calls.items())]
                    text = ''.join(content)
                    raw = SimpleNamespace(model=model, usage=usage, choices=[SimpleNamespace(
                        message=SimpleNamespace(content=text, reasoning_content=''.join(reasoning), tool_calls=raw_calls))])
                    if usage is not None and hasattr(sdk, 'ModelResponse'):
                        raw = sdk.ModelResponse(model=model, usage={
                            'prompt_tokens': usage.prompt_tokens or 0,
                            'completion_tokens': usage.completion_tokens or 0,
                            'total_tokens': (usage.prompt_tokens or 0) + (usage.completion_tokens or 0)},
                            choices=[{'index': 0, 'finish_reason': 'tool_calls' if calls else 'stop',
                                      'message': {'role': 'assistant', 'content': text,
                                          'reasoning_content': ''.join(reasoning), 'tool_calls': [
                                          {'id': value['id'] or f'call-{index}', 'type': 'function',
                                           'function': {'name': value['name'], 'arguments': value['arguments']}}
                                          for index, value in sorted(calls.items())]}}])
                    response = self._to_response(raw, sdk)
                    actual_input = getattr(usage, 'prompt_tokens', None)
                    actual_output = getattr(usage, 'completion_tokens', None)
                    input_known = isinstance(actual_input, int) and not isinstance(actual_input, bool) and actual_input >= 0
                    output_known = isinstance(actual_output, int) and not isinstance(actual_output, bool) and actual_output >= 0
                    if not input_known or not output_known:
                        response.token_usage = {
                            'input': actual_input if input_known else conservative_tokens(json.dumps(messages, ensure_ascii=False) +
                                (json.dumps(tools, ensure_ascii=False) if tools else ''), self.count_tokens),
                            'output': actual_output if output_known else conservative_tokens(''.join(reasoning) + text + ''.join(v['arguments'] for v in calls.values()), self.count_tokens),
                            'cost': None, 'cost_known': False, 'estimated': True}
                    return response
                return await asyncio.wait_for(consume(), timeout=self.timeout)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if started:
                    raise PartialStreamError('模型回复中断，已显示内容未完成；请显式恢复会话') from None
                if attempt >= self.max_retries:
                    raise ModelUnavailable(f'模型流不可用（重试耗尽）: {type(exc).__name__}') from None
            finally:
                if stream is not None:
                    close = getattr(stream, 'aclose', None) or getattr(stream, 'close', None)
                    if close is not None:
                        try:
                            result = close()
                            if inspect.isawaitable(result):
                                await asyncio.wait_for(result, timeout=1)
                        except Exception:
                            pass  # Cleanup errors must not replace the response or safe failure.
            observe(on_delta, StreamEvent('retry'))
            await asyncio.sleep(2 ** attempt)
        raise ModelUnavailable('模型流不可用')

    def _to_response(self, resp: Any, sdk: Any = None) -> LLMResponse:
        """把 litellm 响应收敛为 LLMResponse（各模型差异在此抹平）。"""
        message = resp.choices[0].message
        usage = getattr(resp, "usage", None)
        cost = response_cost(resp, sdk)
        input_tokens, output_tokens = getattr(usage, 'prompt_tokens', None), getattr(usage, 'completion_tokens', None)
        input_tokens = input_tokens if isinstance(input_tokens, int) and input_tokens >= 0 else None
        output_tokens = output_tokens if isinstance(output_tokens, int) and output_tokens >= 0 else None
        return LLMResponse(
            content=message.content or "",
            reasoning_content=getattr(message, 'reasoning_content', None) or '',
            tool_calls=self._normalize_tool_calls(getattr(message, "tool_calls", None)),
            token_usage={
                "input": input_tokens,
                "output": output_tokens,
                "estimated": input_tokens is None or output_tokens is None,
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
        """轻量中文/Latin估算；实际供应商usage仍优先。"""
        return estimate_text_tokens(text)


def _field(value, name, default=None):
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)
