"""工具注册表 + 执行守卫（HARD：Schema 校验→合规→范围→门控→隐蔽修正，五道检查全在代码层）。"""
from __future__ import annotations

from pydantic import ValidationError

from agent.gate.scan_gate import ScanGate
from agent.model.base import NormalizedToolCall
from agent.security.stealth import allowed_target, is_in_scope
from agent.tools.base import BaseTool, ToolResult
from agent.utils.config import Settings
from agent.utils.logger import audit


class ToolRegistry:
    """工具注册与统一执行入口：Agent/CLI 只经此调用工具，保证约束不可绕过。"""

    def __init__(self, settings: Settings, gate: ScanGate, main_target: str) -> None:
        self._settings = settings
        self._gate = gate
        self.main_target = main_target
        self._tools: dict[str, BaseTool] = {}
        self._selected: set[str] = set()
        self._closed = False
        self.plugin_host = None
        from agent.tools.runtime.execution_wait import ToolWaiter
        self.waiter = ToolWaiter(settings)

    def register(self, tool: BaseTool, *, replace: bool = True) -> None:
        """注册工具（同名覆盖，便于测试注入替身）。"""
        reserved = {'ask_user', 'update_plan', 'finish_task', 'recon_safety_policy'}
        if not replace and (tool.name in self._tools or tool.name in reserved):
            raise ValueError(f"Tool name collision: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools)

    def bind_session(self, session_id: str) -> None:
        """Bind only native workspace stores before their first operation."""
        from agent.tools.runtime.workspace import WorkspaceTool
        for tool in self._tools.values():
            if isinstance(tool, WorkspaceTool):
                if tool.store.used and tool.store.session_id != session_id:
                    raise ValueError('Workspace registry already belongs to another session')
                tool.store.session_id = session_id

    def briefs(self) -> list[str]:
        """渐进式披露：先只给一行简介。"""
        return [t.brief() for t in self._tools.values()]

    def specs(self, *, include_deferred: bool = False) -> list[dict]:
        """Expose selected schemas; visibility never grants execution permission."""
        return [t.to_openai_spec() for t in self._tools.values()
                if include_deferred or not getattr(t, 'deferred', False) or t.name in self._selected]

    @property
    def selected_tool_names(self) -> list[str]:
        return sorted(self._selected)

    def select_tools(self, names: list[str]) -> None:
        self._selected = {name for name in names if name in self._tools
                          and getattr(self._tools[name], 'deferred', False)}

    async def aclose(self) -> None:
        """Close connector owners once, including during cancellation/failure."""
        if self._closed:
            return
        self._closed = True
        errors = []
        if self.plugin_host is not None:
            try:
                await self.plugin_host.close()
            except BaseException as exc:
                errors.append(exc)
        try:
            await self.waiter.close()
        except BaseException as exc:
            errors.append(exc)
        import asyncio
        closing = set()
        for tool in self._tools.values():
            close = getattr(tool, 'aclose', None)
            if close is not None:
                closing.add(asyncio.create_task(close()))
        if closing:
            done, pending = await asyncio.wait(closing, timeout=self._settings.TOOL_CLEANUP_SECONDS)
            for task in done:
                if not task.cancelled() and task.exception(): errors.append(task.exception())
            for task in pending:
                task.cancel()
                self.waiter._retain(task, 'connector-cleanup', None, self.main_target)
        if errors:
            raise errors[0]

    async def execute(self, call: NormalizedToolCall, *, on_progress=None, execution_id=None) -> ToolResult:
        """执行一次工具调用的完整守卫链（HARD：任一检查失败立即返回错误结果）。"""
        tool = self._tools.get(call.name)
        if tool is None:
            return ToolResult.err(call.name, f"未知工具 {call.name}，可用: {', '.join(self._tools)}")
        clean_args = {k: v for k, v in call.arguments.items() if not k.startswith("_")}
        try:
            params = tool.params_model.model_validate(clean_args)
        except ValidationError as exc:
            # HARD: Schema 校验失败回填具体字段错误，由上层 LLM 修正重试
            return ToolResult.err(tool.name, f"参数校验失败: {exc.errors()[:3]}")

        ok, reason = allowed_target(params.target, self._settings)
        if not ok:
            audit("compliance_reject", {"tool": tool.name, "target": params.target, "reason": reason})
            return ToolResult.err(tool.name, f"[合规拦截] {reason}")

        if not is_in_scope(params.target, self.main_target):
            audit("scope_reject", {"tool": tool.name, "target": params.target})
            # HARD: 范围硬拦截——关联资产仅记录，任何级别都不得主动扫描
            return ToolResult.err(tool.name, "[范围拦截] 目标超出授权范围，仅可记录为范围外候选，禁止扫描")

        if tool.min_level > self._gate.current_level():
            granted = await self._request_upgrade(tool)
            if not granted:
                return ToolResult.err(
                    tool.name,
                    f"[门控] 当前级别 L{self._gate.current_level()} 不足（需 L{tool.min_level}），保持被动模式",
                )

        if tool.min_level == 2 and self._settings.GATE_PER_STEP_CONFIRM:
            confirmed = await self._gate.confirm_step(
                action=tool.name,
                command=f"{tool.name} {params.target}",
                risk=tool.risk_level,
            )
            if not confirmed:
                return ToolResult.err(tool.name, "[门控] 用户未确认该 L2 动作，已跳过")

        try:
            result = await self.waiter.run(tool, params, execution_id or call.id, on_progress)
            from agent.tools.runtime.result_payload import ResultPayloads
            return ToolResult.model_validate(ResultPayloads(self._settings).prepare(result.model_dump(mode='json'), params.target))
        except Exception as exc:  # noqa: BLE001 —— 任何异常收敛为显式失败（HARD）
            audit("tool_exception", {"tool": tool.name, "error": str(exc)[:300]})
            return ToolResult.err(tool.name, f"工具执行异常: {exc}")

    async def _request_upgrade(self, tool: BaseTool) -> bool:
        """按工具最低级别请求门控升级（L1 一次确认；L2 交由三级门控流程）。"""
        if tool.min_level == 2:
            return self._gate.current_level() >= 2  # HARD: L2 必须先走三级门控解锁
        purpose = f"运行 {tool.name}（{tool.description}）"
        return await self._gate.request_level_1(purpose)


def build_default(settings: Settings, gate: ScanGate, main_target: str, *, session_id=None) -> ToolRegistry:
    """Compatibility wrapper for the built-in provider and enabled plugins."""
    from agent.plugins.builtin_tools import BuiltinTools
    from agent.plugins.host import PluginHost
    registry = ToolRegistry(settings, gate, main_target)
    plugin_host = PluginHost(registry)
    plugin_host.load_enabled(settings, builtin=BuiltinTools(settings, main_target, session_id))
    registry.plugin_host = plugin_host
    return registry
