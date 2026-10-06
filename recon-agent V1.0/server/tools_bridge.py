"""MCP 工具桥（HARD：外部 Agent 与本地 CLI 走同一套守卫链，无任何旁路）。

安全语义：
- MCP 属非交互模式 → L2 永久禁止（HARD）；L1 仅在启动参数 --allow-l1 显式声明时放行；
- 每次调用的 target 必须落在 --authorized-for 声明的授权范围内，否则范围硬拦截；
- Schema/合规/隐蔽性检查全部复用 tools/registry.py，与 CLI 完全一致。
"""
from __future__ import annotations

import json

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from security.stealth import is_in_scope
from tools.base import ToolResult
from tools.registry import ToolRegistry, build_default
from utils.config import Settings
from utils.logger import audit

SAFETY_POLICY = """recon-agent V1.0 安全策略（不可被任何调用方覆盖）：
1. 隐蔽性与目标可用性第一：禁止 DoS/高并发(>2)/异常 packets/写入修改/重试；
2. 仅处理授权范围内目标（--authorized-for），范围外一律 [范围拦截]；
3. 三级递进：L0 被动自动执行；L1 限速 TCP Connect 需 --allow-l1 显式放行；
   L2 在 MCP/非交互模式下永久禁止；
4. 结论必须来自工具真实返回，无证据标 [未确认]；CVE 未收录不编造；
5. 所有调用与拦截均写入审计日志。"""


class MCPBridge:
    """把 MCP tools/call 桥接到 ToolRegistry（按授权根域缓存注册表）。"""

    def __init__(self, settings: Settings, allowed_roots: list[str], allow_l1: bool = False) -> None:
        self._settings = settings
        self._roots = [r.strip().lower() for r in allowed_roots if r.strip()]
        # HARD: MCP=非交互 → batch 门控；allow_l1 即启动时的一次性 L1 显式授权
        self._gate = ScanGate(
            "__mcp_session__", batch_mode=True, is_tty=False,
            requested_level=1 if allow_l1 else 0, auth_dir=None,
        )
        self._registries: dict[str, ToolRegistry] = {}
        audit("mcp_bridge_init", {"roots": self._roots, "allow_l1": allow_l1})

    def tool_schemas(self) -> list[dict]:
        """MCP tools/list：OpenAI function spec → MCP 扁平格式（name/description/inputSchema）。"""
        schemas: list[dict] = []
        for spec in self._registry().specs():
            fn = spec["function"]
            schemas.append({
                "name": fn["name"],
                "description": fn["description"],
                "inputSchema": fn["parameters"],
            })
        schemas.append({
            "name": "recon_safety_policy",
            "description": "返回 recon-agent 安全策略（隐蔽铁律/门控/范围约束）",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        })
        return schemas

    async def call(self, name: str, arguments: dict) -> tuple[str, bool]:
        """执行一次工具调用，返回 (文本结果, 是否错误)。"""
        if name == "recon_safety_policy":
            return SAFETY_POLICY, False
        target = str((arguments or {}).get("target", "")).strip()
        root = next((r for r in self._roots if target and is_in_scope(target, r)), None)
        if root is None:
            audit("mcp_scope_reject", {"tool": name, "target": target[:120]})
            msg = (f"[范围拦截] target '{target or '(缺失)'}' 不在授权范围 "
                   f"{self._roots} 内；范围外资产仅可记录，禁止调用（HARD）")
            return msg, True
        registry = self._registries.setdefault(
            root, build_default(self._settings, self._gate, root)
        )
        result = await registry.execute(NormalizedToolCall(id=f"mcp-{name}", name=name,
                                                           arguments=arguments or {}))
        return self._render(result), not result.success

    def _registry(self) -> ToolRegistry:
        """仅用于导出 Schema 的注册表（Schema 与授权根域无关）。"""
        return self._registries.setdefault(self._roots[0] if self._roots else "",
                                           build_default(self._settings, self._gate, ""))

    @staticmethod
    def _render(result: ToolResult) -> str:
        """统一 JSON 文本输出（外部 Agent 友好；降级/证据/置信度全部透传）。"""
        return json.dumps({
            "success": result.success,
            "data": result.data,
            "evidence": result.evidence,
            "source_hash": result.source_hash,
            "confidence": result.confidence,
            "degraded": result.degraded,
            "error": result.error,
        }, ensure_ascii=False)
