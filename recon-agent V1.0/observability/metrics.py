"""任务指标（HARD：stealth_violations / gate_bypass_attempts 恒应为 0，作为验收红线）。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class TaskMetrics(BaseModel):
    """核心 10 指标 + 辅助指标（对齐开发文档 §12）。"""

    # ---- 核心 10 ----
    tool_calls: int = 0
    tool_success: int = 0
    schema_errors: int = 0
    retries: int = 0
    cache_hits: int = 0
    total_tokens_saved: int = 0
    hallucination_flags: int = 0
    contradiction_count: int = 0
    uncertainty_count: int = 0
    stealth_violations: int = 0          # 应为 0
    # ---- 辅助 ----
    scan_level_reached: int = 0
    gate_confirmations: int = 0
    gate_bypass_attempts: int = 0        # 应为 0
    model_calls: int = 0
    model_fallbacks: int = 0
    cross_platform_issues: int = 0       # 应为 0
    dedup_hits: int = 0
    trimmed_tokens: int = 0
    sandbox_rejections: int = 0
    cve_unknown_count: int = 0
    total_cost_usd: float = 0.0
    extra: dict = Field(default_factory=dict)

    def incr(self, field_name: str, n: int = 1) -> None:
        """安全递增某计数器（字段不存在则忽略，防脚本注入式访问）。"""
        if hasattr(self, field_name):
            setattr(self, field_name, getattr(self, field_name) + n)

    @property
    def tool_success_rate(self) -> float:
        """工具成功率。"""
        return self.tool_success / self.tool_calls if self.tool_calls else 0.0

    @property
    def cache_hit_rate(self) -> float:
        """缓存命中率（去重命中 / 工具调用）。"""
        return self.cache_hits / self.tool_calls if self.tool_calls else 0.0

    def summary(self) -> str:
        """一行摘要（控制台输出）。"""
        return (
            f"工具调用 {self.tool_calls}（成功 {self.tool_success_rate:.0%}）· "
            f"缓存命中 {self.cache_hit_rate:.0%} · 模型调用 {self.model_calls} · "
            f"存疑 {self.uncertainty_count} · 冲突 {self.contradiction_count} · "
            f"隐蔽违规 {self.stealth_violations}（应 0）· 门控绕过 {self.gate_bypass_attempts}（应 0）"
        )
