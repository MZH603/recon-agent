"""模型路由 + fallback 链（HARD：切换模型只改配置/参数，零代码改动）。"""
from __future__ import annotations

import os

from pydantic import BaseModel, Field, SecretStr, field_validator

from model.base import LLMProvider, LLMResponse, ModelUnavailable, PartialStreamError, StreamEvent, observe
from model.litellm_adapter import LiteLLMAdapter
from utils.config import Settings, get_settings, optional_api_key
from utils.logger import warn


class ModelSpec(BaseModel):
    """单个模型的接入规格。"""

    model: str
    api_base: str | None = None
    api_key_env: str | None = None
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)

    _normalize_api_key = field_validator("api_key", mode="before")(optional_api_key)


def resolve_model(
    settings: Settings, override: str | None = None, *, inherit_primary: bool = True,
) -> ModelSpec:
    """解析独立端点/主连接；RECON_* 仅覆盖主模型，fallback 不继承。"""
    environment_model = os.environ.get("RECON_MODEL", "").strip() if inherit_primary else ""
    name = override or environment_model or settings.model.name
    for ep in settings.model.custom_endpoints:
        if name in (ep.get("name"), ep.get("model")):
            spec = ModelSpec(
                model=ep.get("model") or name,
                api_base=ep.get("api_base") or ep.get("base_url"),
                api_key=ep.get("api_key"),
                api_key_env=ep.get("api_key_env"),
            )
            break
    else:
        spec = ModelSpec(
            model=name,
            api_base=settings.model.api_base if inherit_primary else None,
            api_key=settings.model.api_key if inherit_primary else None,
            api_key_env=settings.model.api_key_env if inherit_primary else None,
        )
    if inherit_primary:
        api_base = os.environ.get("RECON_API_BASE", "").strip()
        api_key = optional_api_key(os.environ.get("RECON_API_KEY"))
        updates = {}
        if api_base:
            updates["api_base"] = api_base
        if api_key:
            updates["api_key"] = api_key
        spec = spec.model_copy(update=updates)
    return spec


class FallbackProvider(LLMProvider):
    """按顺序尝试多个 provider，全部失败才抛 ModelUnavailable（HARD：优雅降级不崩溃）。"""

    def __init__(self, providers: list[LLMProvider], names: list[str]) -> None:
        self._providers = providers
        self._names = names

    async def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        last_error: Exception | None = None
        for provider, name in zip(self._providers, self._names):
            try:
                return await provider.complete(messages, tools)
            except ModelUnavailable as exc:
                last_error = exc
                warn(f"模型 {name} 不可用，尝试 fallback 链下一项")
        raise ModelUnavailable(f"全部模型不可达: {last_error}")

    def count_tokens(self, text: str) -> int:
        return self._providers[0].count_tokens(text) if self._providers else max(1, len(text) // 4)

    async def complete_stream(self, messages, tools=None, on_delta=None) -> LLMResponse:
        for index, provider in enumerate(self._providers):
            started = False
            def forward(event):
                nonlocal started
                started |= event.kind in ('chunk', 'content', 'tool', 'usage', 'reasoning')
                observe(on_delta, event)
            try:
                return await provider.complete_stream(messages, tools, forward)
            except ModelUnavailable:
                if started:
                    raise PartialStreamError('模型回复中断，请显式恢复会话') from None
                if index + 1 < len(self._providers):
                    observe(on_delta, StreamEvent('fallback', name=self._names[index + 1]))
        raise ModelUnavailable('全部模型流不可用，请检查配置后恢复会话') from None


def build_provider(settings: Settings | None = None, override: str | None = None, *,
                   connection_override: ModelSpec | None = None) -> LLMProvider:
    """构建 fallback 链；显式指定的凭据缺失时跳过该模型并报备。"""
    settings = settings or get_settings()
    chain = [connection_override if connection_override is not None else resolve_model(settings, override)]
    chain += [resolve_model(settings, fb, inherit_primary=False) for fb in settings.model.fallback]

    providers: list[LLMProvider] = []
    names: list[str] = []
    for index, spec in enumerate(chain):
        if not spec.api_key and spec.api_key_env and not os.environ.get(spec.api_key_env, "").strip():
            role = "主模型" if index == 0 else "备用模型"
            note = "；不影响主模型连接配置" if index else ""
            warn(f"跳过{role} {spec.model}：环境变量 {spec.api_key_env} 未设置且未配置 api_key{note}")
            continue
        providers.append(LiteLLMAdapter(
            model=spec.model,
            api_base=spec.api_base,
            api_key_env=spec.api_key_env,
            api_key=spec.api_key,
            temperature=settings.model.temperature,
            max_retries=settings.model.max_retries,
            timeout=settings.model.timeout,
        ))
        names.append(spec.model)
    if not providers:
        raise ModelUnavailable("无可用模型：请配置 api_key、API Key 环境变量或本地端点（离线仍可出模板报告）")
    return FallbackProvider(providers, names)
