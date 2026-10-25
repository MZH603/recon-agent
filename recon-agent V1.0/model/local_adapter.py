"""本地模型适配器（llama.cpp / Ollama / LM Studio）。
支持零网络离线推理，兼容 OpenAI 格式 API。
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
from typing import Any, Optional

import aiohttp

from model.base import (
    LLMProvider,
    LLMResponse,
    ModelUnavailable,
    NormalizedToolCall,
    StreamEvent,
    PartialStreamError,
    observe,
    conservative_tokens,
)
from utils.config import optional_api_key


class LocalModelAdapter(LLMProvider):
    """本地模型适配器（llama.cpp server / Ollama / LM Studio）。

    - 兼容 OpenAI /v1/chat/completions 格式
    - 支持流式和非流式调用
    - 自动处理工具调用归一化
    - 零网络依赖（仅本地 HTTP）
    """

    def __init__(
        self,
        model: str,
        api_base: str = "http://localhost:11434/v1",  # Ollama 默认
        api_key: str = "ollama",  # Ollama/LM Studio 默认
        temperature: int = 0,
        max_retries: int = 1,
        timeout: int = 120,
        auto_start: bool = False,  # 是否自动启动本地服务
        start_cmd: str = "",  # 启动命令（如 "ollama serve" 或 llama-server 路径）
    ) -> None:
        self.model = model
        self.api_base = api_base.rstrip('/')
        self.api_key = api_key
        self.temperature = temperature
        self.max_retries = max_retries
        self.timeout = timeout
        self.auto_start = auto_start
        self.start_cmd = start_cmd
        self._session: Optional[aiohttp.ClientSession] = None
        self._server_process: Optional[subprocess.Popen] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _maybe_start_server(self):
        """如果配置了自动启动且服务不可达，尝试启动本地服务。"""
        if not self.auto_start or not self.start_cmd:
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.api_base}/models", timeout=aiohttp.ClientTimeout(total=2)):
                    return  # 已经在运行
        except Exception:
            pass
        # 启动服务
        self._server_process = subprocess.Popen(
            self.start_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        # 等待服务就绪
        for _ in range(30):
            await asyncio.sleep(1)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{self.api_base}/models", timeout=aiohttp.ClientTimeout(total=2)):
                        return
            except Exception:
                continue
        raise ModelUnavailable(f"本地模型服务启动失败: {self.start_cmd}")

    async def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        """非流式调用。"""
        await self._maybe_start_server()

        session = await self._get_session()
        url = f"{self.api_base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                async with session.post(url, headers=headers, json=payload) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise ModelUnavailable(f"本地模型 HTTP {resp.status}: {text}")
                    data = await resp.json()
                    return self._to_response(data)
            except aiohttp.ClientError as exc:
                last_error = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
        raise ModelUnavailable(f"本地模型不可达（重试耗尽）: {last_error}")

    async def complete_stream(self, messages: list[dict], tools: list[dict] | None = None, on_delta=None) -> LLMResponse:
        """流式调用。"""
        await self._maybe_start_server()

        session = await self._get_session()
        url = f"{self.api_base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        content, reasoning, calls = [], [], {}
        usage = None
        model_name = self.model

        for attempt in range(self.max_retries + 1):
            stream = None
            try:
                async with session.post(url, headers=headers, json=payload) as resp:
                    if resp.status != 200:
                        text = await resp.text()
                        raise ModelUnavailable(f"本地模型流 HTTP {resp.status}: {text}")

                    started = False
                    async for line in resp.content:
                        line = line.decode('utf-8').strip()
                        if not line or not line.startswith('data: '):
                            continue
                        if line == 'data: [DONE]':
                            break
                        started = True
                        try:
                            chunk = json.loads(line[6:])
                        except json.JSONDecodeError:
                            continue

                        model_name = chunk.get('model', model_name)
                        observe(on_delta, StreamEvent('chunk'))

                        chunk_usage = chunk.get('usage')
                        if chunk_usage:
                            usage = chunk_usage
                            observe(on_delta, StreamEvent('usage', token_usage={
                                'input': usage.get('prompt_tokens', 0),
                                'output': usage.get('completion_tokens', 0)
                            }))

                        for choice in chunk.get('choices', []) or []:
                            if choice.get('index', 0) != 0:
                                continue
                            reason = choice.get('finish_reason')
                            if reason and reason not in ('stop', 'tool_calls', 'function_call'):
                                raise PartialStreamError('模型流未完整结束')

                            delta = choice.get('delta', {})
                            thought = delta.get('reasoning_content')
                            if thought:
                                reasoning.append(thought)
                                observe(on_delta, StreamEvent('reasoning', content=thought))

                            text = delta.get('content')
                            if text:
                                content.append(text)
                                observe(on_delta, StreamEvent('content', content=text))

                            for call in delta.get('tool_calls', []) or []:
                                index = call.get('index', 0)
                                entry = calls.setdefault(index, {'id': '', 'name': '', 'arguments': ''})
                                entry['id'] += call.get('id', '')
                                func = call.get('function', {})
                                entry['name'] += func.get('name', '')
                                entry['arguments'] += func.get('arguments', '')
                                observe(on_delta, StreamEvent('tool', index=index,
                                                                name=func.get('name', ''),
                                                                arguments=func.get('arguments', '')))

                    if not started:
                        raise ModelUnavailable('本地模型流未返回响应')

                    # Build response
                    text = ''.join(content)
                    reasoning_text = ''.join(reasoning)
                    raw_calls = []
                    for _, value in sorted(calls.items()):
                        raw_calls.append(NormalizedToolCall(
                            id=value['id'] or f"call-{len(raw_calls)}",
                            name=value['name'],
                            arguments=json.loads(value['arguments']) if value['arguments'] else {}
                        ))

                    input_tokens = usage.get('prompt_tokens', 0) if usage else None
                    output_tokens = usage.get('completion_tokens', 0) if usage else None

                    return LLMResponse(
                        content=text,
                        reasoning_content=reasoning_text,
                        tool_calls=raw_calls,
                        token_usage={
                            "input": input_tokens,
                            "output": output_tokens,
                            "estimated": input_tokens is None or output_tokens is None,
                            "cost": None, "cost_known": False,
                        },
                        model=model_name
                    )

            except aiohttp.ClientError as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    raise ModelUnavailable(f"本地模型流不可用: {type(last_error).__name__}") from None
            except Exception as exc:
                if started:
                    raise PartialStreamError('模型回复中断，已显示内容未完成') from None
                if attempt >= self.max_retries:
                    raise ModelUnavailable(f"本地模型流不可用: {type(exc).__name__}") from None
            await asyncio.sleep(2 ** attempt)
        raise ModelUnavailable('本地模型流不可用（重试耗尽）')

    def _to_response(self, data: dict) -> LLMResponse:
        """把本地模型响应收敛为 LLMResponse。"""
        message = data['choices'][0]['message']
        usage = data.get('usage')
        tool_calls = self._normalize_tool_calls(message.get('tool_calls'))
        return LLMResponse(
            content=message.get('content') or "",
            reasoning_content=message.get('reasoning_content') or '',
            tool_calls=tool_calls,
            token_usage={
                "input": usage.get('prompt_tokens') if usage else None,
                "output": usage.get('completion_tokens') if usage else None,
                "estimated": usage is None,
                "cost": None, "cost_known": False,
            },
            model=data.get('model', self.model),
        )

    def _normalize_tool_calls(self, raw: Any) -> list[NormalizedToolCall]:
        """OpenAI 格式 tool_call → NormalizedToolCall。"""
        calls: list[NormalizedToolCall] = []
        if not raw:
            return calls
        for index, tc in enumerate(raw):
            function = tc.get('function')
            if not function:
                continue
            args_raw = function.get('arguments', '{}') or '{}'
            try:
                arguments = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
            except json.JSONDecodeError:
                arguments = {}
            calls.append(NormalizedToolCall(
                id=tc.get('id') or f"call-{index}",
                name=function.get('name', ''),
                arguments=arguments,
            ))
        return calls

    async def aclose(self):
        """清理资源。"""
        if self._session and not self._session.closed:
            await self._session.close()
        if self._server_process:
            self._server_process.terminate()
            try:
                self._server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._server_process.kill()