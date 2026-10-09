"""ReAct 主循环（HARD：单轮 ≤5 步超步切规划；校验失败回填重试 ≤2；预算三档联动）。"""
from __future__ import annotations

from efficiency.budget_guard import BudgetExhausted
from efficiency.deduplicator import CallDeduplicator
from hallucination.contradiction import ContradictionDetector
from hallucination.evidence import EvidenceStore
from model.base import LLMResponse, NormalizedToolCall, parse_xml_tool_calls
from observability.metrics import TaskMetrics
from tools.base import ToolResult
from tools.registry import ToolRegistry
from utils.cache import SQLiteCache
from utils.config import Settings, get_settings
from utils.logger import err, info, ok, warn

MAX_STEPS_PER_PLAN = 5   # HARD: ≤5 步，超步切规划
MAX_PLANS = 3
MAX_SCHEMA_RETRIES = 2   # HARD: 校验回填重试上限


class ReconAgent:
    """LLM 编排器：决策（选工具+参数）→ 守卫执行 → 观察 → 再决策。"""

    def __init__(
        self,
        target: str,
        registry: ToolRegistry,
        llm,
        metrics: TaskMetrics | None = None,
        settings: Settings | None = None,
        cache: SQLiteCache | None = None,
    ) -> None:
        self.target = target
        self._registry = registry
        self._llm = llm
        self._metrics = metrics or TaskMetrics()
        self._settings = settings or get_settings()
        self._dedup = CallDeduplicator(self._settings, cache)
        self.evidence = EvidenceStore()
        self.contradictions = ContradictionDetector()
        self._last_signature = ""  # 同一失败调用的重复计数（回填重试用）

    @property
    def metrics(self) -> TaskMetrics:
        return self._metrics

    async def run(self, goal: str, system_prompt: str) -> dict:
        """主循环：返回 {answer, results, exhausted}。"""
        try:
            return await self._run(goal, system_prompt)
        finally:
            await self._registry.aclose()

    async def _run(self, goal: str, system_prompt: str) -> dict:
        from core.context import ContextManager

        ctx = ContextManager(self._settings)
        ctx.set_system(system_prompt)
        ctx.add_user(goal)
        results: list[ToolResult] = []
        exhausted = False
        for _plan in range(MAX_PLANS):
            steps = 0
            while steps < MAX_STEPS_PER_PLAN:
                try:
                    resp = await self._llm.complete(ctx.messages, self._registry.specs())
                except BudgetExhausted:
                    exhausted = True  # HARD: 预算耗尽 → 立即收敛出报告
                    break
                self._metrics.incr("model_calls")
                ctx.add_assistant_response(resp)
                calls = resp.tool_calls or parse_xml_tool_calls(resp.content)
                if not calls:
                    return {"answer": resp.content, "results": results, "exhausted": exhausted,
                            "context": ctx}
                for call in calls:
                    result = await self._execute(call)
                    results.append(result)
                    ctx.add_tool_result(call, result, native=bool(resp.tool_calls))
                    steps += 1
                ctx.maybe_compact()
            if exhausted:
                break
            # HARD: 超过 5 步 → 切规划（结构化摘要，不用自由文本）
            ctx.add_user(
                "[系统] 已达单轮 5 步上限。请按 StateSummary 总结：目标/已完成/当前状态/下一步，"
                "然后继续执行剩余步骤。"
            )
        return {"answer": "[INCOMPLETE] 达到规划轮次上限，任务未完成，请人工复核",
                "results": results, "exhausted": exhausted, "context": ctx}

    async def _execute(self, call: NormalizedToolCall) -> ToolResult:
        """单次调用守卫：去重 → 预算 → 注册表五道检查 → 证据登记。"""
        cacheable = getattr(self._registry.get(call.name), 'cacheable', True)
        skip, reason = self._dedup.should_skip(call, self.target) if cacheable else (False, 'stateful')
        if skip:
            self._metrics.incr("cache_hits")
            self._metrics.incr("dedup_hits")
            info(f"去重命中: {call.name} {call.arguments.get('target', '')}")
            return ToolResult.err(call.name, reason)  # 复用提示以错误结果形态回注
        min_level = self._tool_min_level(call.name)
        if not self._llm.guard.allows(min_level):  # HARD: 预算档位联动
            return ToolResult.err(call.name,
                                  f"[预算收敛] 当前预算档位下不允许 L{min_level} 级动作，仅被动采集")
        result = await self._registry.execute(call)
        self._update_metrics(call, result)
        if result.success and cacheable:
            self._dedup.record(call, self.target, result.stdout[:200])
        self.evidence.add(result)
        self._observe_contradictions(result)
        return result

    def _tool_min_level(self, name: str) -> int:
        tool = self._registry.get(name)
        return tool.min_level if tool else 0

    def _update_metrics(self, call: NormalizedToolCall, result: ToolResult) -> None:
        """按结果更新指标（拦截类错误计入绕过尝试）。"""
        self._metrics.incr("tool_calls")
        if result.success:
            self._metrics.incr("tool_success")
        if "参数校验失败" in result.error:
            self._metrics.incr("schema_errors")
            if call.name == self._last_signature:
                self._metrics.incr("retries")
            else:
                self._last_signature = call.name
        if any(tag in result.error for tag in ("[范围拦截]", "[门控]", "[合规拦截]")):
            self._metrics.incr("gate_bypass_attempts")
        if result.degraded:
            warn(f"[降级模式] {result.name} 置信度下调至 {result.confidence:.2f}")

    def _observe_contradictions(self, result: ToolResult) -> None:
        """把工具结果里的技术栈断言登记进矛盾检测器。"""
        tech = result.data.get("tech") if isinstance(result.data, dict) else None
        if not tech:
            return
        for category, item in tech.items():
            self.contradictions.observe(result.data.get("host", self.target),
                                        category, str(item.get("name", "")),
                                        (item.get("source") or "")[:60])
            for alt in item.get("alternatives", []):
                self.contradictions.observe(result.data.get("host", self.target),
                                            category, str(alt.get("name", "")),
                                            (alt.get("source") or "")[:60])
        conflicts = self.contradictions.conflicts()
        if conflicts:
            self._metrics.incr("contradiction_count", len(conflicts))
            err("[冲突] 检测到多源矛盾，已标注 [冲突，需人工核实]，不二选一")
