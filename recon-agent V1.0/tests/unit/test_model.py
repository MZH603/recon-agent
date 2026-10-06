"""模型接入层测试（XML 协议解析 / tool_call 归一化 / 模型路由 / fallback）。"""
import asyncio
from types import SimpleNamespace

import pytest

from model.base import ModelUnavailable, NormalizedToolCall, parse_xml_tool_calls
from model.litellm_adapter import LiteLLMAdapter
from model.registry import build_provider, resolve_model
from utils.config import Settings


def test_parse_xml_tool_calls():
    text = """
    <tool_call>
      <tool_name>dns_query</tool_name>
      <parameters><target>example.com</target></parameters>
      <purpose>查 A 记录</purpose>
      <risk_level>低</risk_level>
    </tool_call>
    """
    calls = parse_xml_tool_calls(text)
    assert len(calls) == 1
    assert calls[0].name == "dns_query"
    assert calls[0].arguments["target"] == "example.com"
    assert calls[0].arguments["_risk_level"] == "低"


def test_parse_xml_ignores_garbage():
    assert parse_xml_tool_calls("<tool_call><broken") == []


def test_tool_call_normalized_across_providers():
    adapter = LiteLLMAdapter("gpt-4o-mini")
    fake = [SimpleNamespace(id="call_1", function=SimpleNamespace(name="nmap_scan",
            arguments='{"target": "example.com", "ports": "80"}'))]
    calls = adapter._normalize_tool_calls(fake)
    assert calls[0] == NormalizedToolCall(id="call_1", name="nmap_scan",
                                          arguments={"target": "example.com", "ports": "80"})
    # arguments 为坏 JSON → 空参数（显式交上层校验回填，不猜测）
    bad = adapter._normalize_tool_calls([SimpleNamespace(id="c2",
          function=SimpleNamespace(name="t", arguments="{bad json"))])
    assert bad[0].arguments == {}


def test_switch_model_without_code_change():
    settings = Settings()
    settings.model.custom_endpoints = [{"name": "deepseek", "base_url": "https://x/v1",
                                        "api_key_env": "DEEPSEEK_API_KEY", "model": "deepseek-chat"}]
    spec = resolve_model(settings, "deepseek")
    assert spec.model == "deepseek-chat" and spec.api_base == "https://x/v1"
    assert resolve_model(settings, "gpt-4o").model == "gpt-4o"  # 直连类直接透传


def test_unknown_model_raises_clear_error(monkeypatch):
    # 端点缺 key → 跳过；全链为空 → 明确错误（HARD：清晰报错而非静默）
    settings = Settings()
    settings.model.custom_endpoints = [{"name": "x", "base_url": "u",
                                        "api_key_env": "NOPE_KEY", "model": "m"}]
    settings.model.fallback = []
    monkeypatch.delenv("NOPE_KEY", raising=False)
    with pytest.raises(ModelUnavailable):
        build_provider(settings, "x")  # 全链（主+fallback）都缺 key → 明确报错


def test_count_tokens_cheap_estimate():
    adapter = LiteLLMAdapter("m")
    assert adapter.count_tokens("a" * 400) == 100


def test_fallback_provider_order():
    from model.base import LLMProvider, LLMResponse
    from model.registry import FallbackProvider

    class Boom(LLMProvider):
        async def complete(self, messages, tools=None):
            raise ModelUnavailable("down")
        def count_tokens(self, text):
            return 1

    class Ok(LLMProvider):
        async def complete(self, messages, tools=None):
            return LLMResponse(content="ok")
        def count_tokens(self, text):
            return 1

    chain = FallbackProvider([Boom(), Ok()], ["a", "b"])
    resp = asyncio.run(chain.complete([{"role": "user", "content": "hi"}]))
    assert resp.content == "ok"
    with pytest.raises(ModelUnavailable):
        asyncio.run(FallbackProvider([Boom()], ["a"]).complete([]))
