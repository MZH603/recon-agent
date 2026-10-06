"""预算三档监控（HARD：60% 预警收敛 L2 / 80% 停主动 / 100% 终止 LLM 调用 + 报告水印）。"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class BudgetState(str, Enum):
    """预算状态四档。"""

    HEALTHY = "HEALTHY"
    WARNING = "WARNING"          # >60%：停止 L2 新动作
    CONVERGING = "CONVERGING"    # >80%：停止主动探测，仅被动 + 出报告
    EXHAUSTED = "EXHAUSTED"      # 100%：立即终止 LLM 调用，模板渲染已有结果


class BudgetExhausted(RuntimeError):
    """预算耗尽（上层捕获后走离线模板报告 + 水印）。"""


class BudgetGuard(BaseModel):
    """按 token / 成本双维度监控，取更先触发的档位。"""

    max_tokens: int = 60_000
    max_cost: float = 2.0
    used_tokens: int = 0
    used_cost: float = 0.0

    def register(self, input_tokens: int, output_tokens: int, cost: float = 0.0) -> None:
        """记录一次模型调用的消耗。"""
        self.used_tokens += input_tokens + output_tokens
        self.used_cost += cost

    def state(self) -> BudgetState:
        """当前预算档位。"""
        ratio = max(
            self.used_tokens / self.max_tokens if self.max_tokens else 0,
            self.used_cost / self.max_cost if self.max_cost else 0,
        )
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
            raise BudgetExhausted("预算耗尽（HARD：终止 LLM 调用，转模板报告）")
        return state

    def allows(self, min_level: int) -> bool:
        """按档位判断是否允许发起某级别动作（HARD：WARNING 收敛 L2，CONVERGING 仅被动）。"""
        state = self.state()
        if state is BudgetState.EXHAUSTED:
            return False
        if state is BudgetState.CONVERGING:
            return min_level == 0
        if state is BudgetState.WARNING:
            return min_level <= 1
        return True

    def watermark_required(self) -> bool:
        """EXHAUSTED 时报告必须带 [INCOMPLETE] 水印（HARD）。"""
        return self.state() is BudgetState.EXHAUSTED
