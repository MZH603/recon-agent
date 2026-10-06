"""LLM 服务桥接（模型 fallback + 预算联动；HARD：EXHAUSTED 时拒绝一切模型调用）。"""
from __future__ import annotations

from efficiency.budget_guard import BudgetGuard
from model.base import LLMProvider, LLMResponse
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
        self.guard.register(resp.token_usage.get("input", 0), resp.token_usage.get("output", 0))
        return resp

    def count_tokens(self, text: str) -> int:
        """token 粗估透传。"""
        return self.provider.count_tokens(text)
