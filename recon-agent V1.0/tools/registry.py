"""工具注册表 + 执行守卫（HARD：Schema 校验→合规→范围→门控→隐蔽修正，五道检查全在代码层）。"""
from __future__ import annotations

from pydantic import ValidationError

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from security.stealth import allowed_target, is_in_scope
from tools.base import BaseTool, ToolResult
from tools.builtin.dns_query import DNSQueryTool
from tools.builtin.fingerprint import FingerprintTool
from tools.builtin.port_scan import BuiltinPortScan
from tools.builtin.deep_fingerprint import DeepFingerprintTool
from tools.builtin.dir_enum import DirEnumTool
from tools.builtin.httpx_tool import HttpxProbeTool
from tools.builtin.nmap_tool import NmapTool
from tools.builtin.script_probe import ScriptProbeTool
from tools.builtin.subdomain_enum import SubdomainEnumTool
from tools.builtin.system_scan import SystemScanTool
from tools.builtin.takeover_check import TakeoverCheckTool
from tools.builtin.wayback_urls import WaybackTool
from utils.config import Settings
from utils.logger import audit


class ToolRegistry:
    """工具注册与统一执行入口：Agent/CLI 只经此调用工具，保证约束不可绕过。"""

    def __init__(self, settings: Settings, gate: ScanGate, main_target: str) -> None:
        self._settings = settings
        self._gate = gate
        self.main_target = main_target
        self._tools: dict[str, BaseTool] = {}
        self._selected: set[str] = set()
        self._closed = False
        from tools.runtime.execution_wait import ToolWaiter
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
        from tools.runtime.workspace import WorkspaceTool
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
        await self.waiter.close()
        import asyncio
        closing = set()
        for tool in self._tools.values():
            close = getattr(tool, 'aclose', None)
            if close is not None:
                closing.add(asyncio.create_task(close()))
        errors = []
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
            from tools.runtime.result_payload import ResultPayloads
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
    """构建默认工具集：外部工具缺失时各工具内部自动降级到 builtin 实现。"""
    registry = ToolRegistry(settings, gate, main_target)
    registry.register(DNSQueryTool(settings))
    registry.register(SubdomainEnumTool(settings))  # L0：子域枚举+递归拓线
    registry.register(FingerprintTool(settings))
    registry.register(HttpxProbeTool(settings))
    registry.register(NmapTool(settings))
    registry.register(BuiltinPortScan(settings))
    registry.register(DirEnumTool(settings))      # L2：三级门控 + 逐项确认
    registry.register(ScriptProbeTool(settings))  # L2：三层沙箱
    registry.register(DeepFingerprintTool(settings))  # L2：WhatWeb 式深度指纹
    registry.register(TakeoverCheckTool(settings))  # L0：子域接管候选
    registry.register(WaybackTool(settings))        # L0：历史端点
    registry.register(SystemScanTool(settings))     # L2：系统安全工具网关
    from tools.builtin.api_recon import ApiReconTool
    from tools.adapters.custom import build_custom_tools
    from tools.runtime.evidence_tools import build_evidence_tools
    from tools.adapters.mcp_tools import build_mcp_tools
    from tools.runtime.catalog import ToolCatalogTool
    registry.register(ApiReconTool(settings), replace=False)
    registry.register(ToolCatalogTool(registry), replace=False)
    for tool in [*build_evidence_tools(settings), *build_custom_tools(settings),
                 *build_mcp_tools(settings, main_target)]:
        registry.register(tool, replace=False)
    from tools.adapters.scanners import build_scanner_tools
    from tools.adapters.search import build_search_tools
    from tools.adapters.proxy import build_proxy_tools
    from tools.runtime.knowledge import build_knowledge_tools
    from tools.runtime.workspace import build_workspace_tools
    for tool in [*build_scanner_tools(settings), *build_search_tools(settings),
                 *build_proxy_tools(settings), *build_knowledge_tools(settings),
                 *build_workspace_tools(settings, session_id)]:
        registry.register(tool, replace=False)
    return registry
