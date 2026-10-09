"""Lazy model initialization and session budget ownership."""
from __future__ import annotations

import math

from efficiency.budget_guard import BudgetGuard, BudgetExhausted
from model.base import ModelUnavailable, response_events, estimate_text_tokens


class LazyLLM:
    def __init__(self, settings, model, factory=None, *, connection_override=None):
        self.settings, self.model, self.factory = settings, model, factory
        self.connection_override = connection_override
        self.service = None
        self.guard = BudgetGuard(max_tokens=0,
                                 max_cost=settings.MAX_COST_PER_TASK)

    async def complete(self, messages, tools=None):
        if self.service is None:
            try:
                if self.factory is None:
                    from model.service import LLMService
                    kwargs = {} if self.connection_override is None else {'connection_override': self.connection_override}
                    self.service = LLMService(self.settings, self.model, guard=self.guard, **kwargs)
                else:
                    self.service = self.factory(self.settings, self.model)
                    self.service.guard = self.guard
            except Exception as exc:
                raise ModelUnavailable('模型配置不可用，请检查配置后恢复会话') from exc
        try:
            return await self.service.complete(messages, tools)
        except (ModelUnavailable, BudgetExhausted):
            raise
        except Exception as exc:
            raise ModelUnavailable('模型配置或响应不可用，请检查配置后恢复会话') from exc

    async def complete_stream(self, messages, tools=None, on_delta=None):
        # Construct lazily without a preliminary model request.
        if self.service is None:
            try:
                if self.factory is None:
                    from model.service import LLMService
                    kwargs = {} if self.connection_override is None else {'connection_override': self.connection_override}
                    self.service = LLMService(self.settings, self.model, guard=self.guard, **kwargs)
                else:
                    self.service = self.factory(self.settings, self.model)
                    self.service.guard = self.guard
            except Exception:
                raise ModelUnavailable('模型配置不可用，请检查配置后恢复会话') from None
        try:
            stream = getattr(self.service, 'complete_stream', None)
            if stream is not None:
                return await stream(messages, tools, on_delta)
            response = await self.service.complete(messages, tools)
            response_events(response, on_delta)
            return response
        except (ModelUnavailable, BudgetExhausted):
            raise
        except Exception:
            raise ModelUnavailable('模型配置或响应不可用，请检查配置后恢复会话') from None

    def count_tokens(self, text):
        method = getattr(self.service, 'count_tokens', None)
        return method(text) if method else math.ceil(estimate_text_tokens(text) * 1.25)
