"""L2 沙箱脚本探测工具（HARD：三级门控 + 逐项确认 + AST/Bandit 三层沙箱，缺一不可）。"""
from __future__ import annotations

from pydantic import BaseModel, Field

from scripts import sandbox
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings


class ScriptProbeParams(BaseModel):
    """脚本探测参数：LLM 生成的 Python 代码（≤50 行 / ≤4000 字符）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$")
    code: str = Field(..., min_length=10, max_length=4000,
                      description="仅标准库、单线程、限速的探测脚本（顶层 docstring 说明用途）")


class ScriptProbeTool(BaseTool):
    """把 LLM 编写的探测脚本放进三层沙箱执行（AST + Bandit + 运行时隔离）。

    HARD:
    - min_level=2：必须先走三级门控解锁，再经注册表逐项确认；
    - 脚本黑名单：禁 os/sys/subprocess/eval/exec/open/文件写/网络外传；
    - bandit 缺失即拒绝执行（沙箱三层缺一不可）。
    """

    name = "script_probe"
    description = "在三层沙箱中执行 LLM 生成的探测脚本（仅标准库/限速，L2 门控）"
    risk_level = "高"
    min_level = 2
    params_model = ScriptProbeParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        """逐项确认已由注册表门控完成（GATE_PER_STEP_CONFIRM），此处执行沙箱。"""
        assert isinstance(params, ScriptProbeParams)
        ret, out, err = await sandbox.execute(params.code, confirmed=True, settings=self._settings)
        if ret in (124, 125, 126):
            return ToolResult.err(self.name, err or f"[沙箱] 拒绝/超时（exit={ret}）")
        return ToolResult(
            name=self.name,
            success=ret == 0,
            stdout=out[:1500],
            stderr=err[:500],
            exit_code=ret,
            data={"exit_code": ret, "output": out[:1000]},
            evidence=[f"沙箱脚本执行 exit={ret}（AST+Bandit 校验通过，超时 {self._settings.SANDBOX_TIMEOUT}s）"],
            confidence=0.6,
        )
