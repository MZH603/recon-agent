"""L2 工具门控测试（dir_enum / script_probe 必须走三级门控 + 逐项确认）。"""
import asyncio

import pytest
from pydantic import ValidationError

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.dir_enum import DirEnumParams
from tools.registry import build_default
from utils.config import get_settings


def make_registry(batch: bool = True, unlocked: bool = False):
    """构造测试注册表；unlocked=True 时注入已解锁门控。"""
    settings = get_settings()
    gate = ScanGate("example.com", batch_mode=batch, is_tty=not batch,
                    auth_dir=None, requested_level=2 if unlocked else 0)
    if unlocked:
        gate.unlock_level_2()  # 测试注入：跳过交互（等效于三次确认已通过）
    return build_default(settings, gate, "example.com"), gate


class _StubDirEnum:
    """桩工具：验证门控层放行/拦截，不做网络请求。"""

    name = "dir_enum"
    description = "stub"
    risk_level = "高"
    min_level = 2
    params_model = DirEnumParams

    def __init__(self) -> None:
        self.called = False

    async def run(self, params) -> "object":
        from tools.base import ToolResult

        self.called = True
        return ToolResult(name=self.name, success=True, data={"stub": True})


def _install_stub(registry) -> _StubDirEnum:
    stub = _StubDirEnum()
    registry._tools["dir_enum"] = stub  # 覆盖真实工具（门控层测试不联网）
    return stub


def test_golden_11_dir_enum_blocked_without_l2_unlock():
    # 诱导："把目录枚举跑一下" → 未解锁 L2 必须被拒
    registry, _ = make_registry(batch=True)
    stub = _install_stub(registry)
    result = asyncio.run(registry.execute(
        NormalizedToolCall(id="1", name="dir_enum", arguments={"target": "sub.example.com"})))
    assert not result.success and "[门控]" in result.error
    assert not stub.called


def test_dir_enum_passes_after_unlock_with_per_step_confirm():
    # 解锁 L2 后，逐项确认通过 → 门控放行，桩工具真正执行
    registry, gate = make_registry(batch=False, unlocked=True)
    stub = _install_stub(registry)

    async def fake_prompt(prompt: str) -> str:
        return "yes"  # 逐项确认注入

    gate._prompt_fn = fake_prompt
    result = asyncio.run(registry.execute(
        NormalizedToolCall(id="2", name="dir_enum", arguments={"target": "sub.example.com"})))
    assert result.success, result.error
    assert stub.called
    assert any(c["kind"] == "l2_action" for c in gate.confirm_log)  # 逐项确认已发生


def test_dir_enum_per_step_denial_blocks_execution():
    # 解锁但逐项确认拒绝 → 工具不执行
    registry, gate = make_registry(batch=False, unlocked=True)
    stub = _install_stub(registry)

    async def fake_prompt(prompt: str) -> str:
        return "no"

    gate._prompt_fn = fake_prompt
    result = asyncio.run(registry.execute(
        NormalizedToolCall(id="3", name="dir_enum", arguments={"target": "sub.example.com"})))
    assert not result.success and "[门控]" in result.error
    assert not stub.called


def test_dir_enum_paths_bounded():
    from tools.dir_enum import MAX_PATHS

    assert MAX_PATHS == 80  # HARD: 泄露嗅探扩容后的上限
    with pytest.raises(ValidationError):
        DirEnumParams(target="example.com", paths=[f"/p{i}" for i in range(81)])
    params = DirEnumParams(target="example.com", paths=[f"/p{i}" for i in range(80)])
    assert len(params.paths) == 80
    assert DirEnumParams(target="example.com").max_paths == 60  # 默认探测 60 条


def test_script_probe_registered_and_gated():
    # script_probe 同样 min_level=2：未解锁被拒
    registry, _ = make_registry(batch=True)
    result = asyncio.run(registry.execute(NormalizedToolCall(
        id="4", name="script_probe",
        arguments={"target": "example.com", "code": '"""probe"""\nprint("x")'})))
    assert not result.success and "[门控]" in result.error


def test_l2_tools_listed_with_high_risk():
    registry, _ = make_registry()
    briefs = "\n".join(registry.briefs())
    assert "dir_enum" in briefs and "script_probe" in briefs
    assert registry.get("dir_enum").risk_level == "高"
    assert registry.get("script_probe").min_level == 2
