"""任务成本预算监控：60%/80% 软提示，100% 暂停模型调用。"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class BudgetState(str, Enum):
    """预算状态四档。"""

    HEALTHY = "HEALTHY"
    WARNING = "WARNING"          # >=60%：软提示
    CONVERGING = "CONVERGING"    # >=80%：软提示
    EXHAUSTED = "EXHAUSTED"      # 100%：立即终止 LLM 调用，模板渲染已有结果


class BudgetExhausted(RuntimeError):
    """预算耗尽（上层捕获后走离线模板报告 + 水印）。"""


class BudgetGuard(BaseModel):
    """按成本监控；累计 token 仅用于用量记账。"""

    max_tokens: int = 0  # Deprecated compatibility field; never enforced.
    max_cost: float = 2.0
    used_tokens: int = 0
    used_cost: float = 0.0

    def register(self, input_tokens: int, output_tokens: int, cost: float = 0.0) -> None:
        """记录一次模型调用的消耗。"""
        self.used_tokens += input_tokens + output_tokens
        self.used_cost += cost

    def state(self) -> BudgetState:
        """当前预算档位。"""
        ratio = self.used_cost / self.max_cost if self.max_cost else 0
        if ratio >= 1.0:
            return BudgetState.EXHAUSTED
        if ratio >= 0.8:
            return BudgetState.CONVERGING
        if ratio >= 0.6:
            return BudgetState.WARNING
        return BudgetState.HEALTHY

    def check(self) -> BudgetState:
        """供每次 LLM 调用前检查；EXHAUSTED 直接抛异常（HARD）。"""
        state = self.state()
        if state is BudgetState.EXHAUSTED:
            raise BudgetExhausted("任务成本预算达到硬上限；用 /budget cost USD 追加成本预算后继续，已用量不会清零。")
        return state

    def allows(self, min_level: int) -> bool:
        """Soft thresholds only advise; the hard limit blocks new actions."""
        return self.state() is not BudgetState.EXHAUSTED

    def watermark_required(self) -> bool:
        """EXHAUSTED 时报告必须带 [INCOMPLETE] 水印（HARD）。"""
        return self.state() is BudgetState.EXHAUSTED
