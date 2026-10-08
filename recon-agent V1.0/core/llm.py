"""LLM 服务桥接（模型 fallback + 预算联动；HARD：EXHAUSTED 时拒绝一切模型调用）。"""
from __future__ import annotations

from model.cost import valid_cost
from efficiency.budget_guard import BudgetGuard
from model.base import LLMProvider, LLMResponse, StreamUsage, observe
from model.registry import build_provider
from utils.config import Settings, get_settings


class LLMService:
    """Agent 使用的统一模型入口：调用前检查预算，调用后登记消耗。"""

    def __init__(self, settings: Settings | None = None, model_override: str | None = None,
                 guard: BudgetGuard | None = None) -> None:
        self._settings = settings or get_settings()
        self.guard = guard or BudgetGuard(
            max_tokens=self._settings.MAX_TOKENS_PER_TASK,
            max_cost=self._settings.MAX_COST_PER_TASK,
        )
        self.provider: LLMProvider = build_provider(self._settings, model_override)
        self.model_name = model_override or self._settings.model.name
        self.used_fallback = False

    async def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        """预算检查 → 模型调用 → 消耗登记（ModelUnavailable 向上传播交由降级处理）。"""
        self.guard.check()  # HARD: EXHAUSTED 抛 BudgetExhausted
        resp = await self.provider.complete(messages, tools)
        self.guard.register(resp.token_usage.get("input", 0), resp.token_usage.get("output", 0),
                            valid_cost(resp.token_usage.get("cost")) or 0.0)
        return resp

    def count_tokens(self, text: str) -> int:
        """token 粗估透传。"""
        return self.provider.count_tokens(text)

    async def complete_stream(self, messages, tools=None, on_delta=None) -> LLMResponse:
        self.guard.check()
        partial = StreamUsage()
        finished = False
        def forward(event):
            partial.add(event)
            observe(on_delta, event)
        try:
            response = await self.provider.complete_stream(messages, tools, forward)
            self.guard.register(response.token_usage.get('input', 0), response.token_usage.get('output', 0),
                                valid_cost(response.token_usage.get('cost')) or 0.0)
            finished = True
            return response
        finally:
            if partial.started and not finished:
                usage = partial.partial(messages, self.count_tokens, tools)
                self.guard.register(usage['input'], usage['output'])
