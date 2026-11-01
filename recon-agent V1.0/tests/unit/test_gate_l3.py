"""L3 门控测试（CONFIRM 3 三步确认 / 签名级别字段 / min_level=3 工具拦截 / tier1 确认）。"""
import asyncio

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.registry import build_default
from utils.config import get_settings


def _canned(answers: list[str]):
    queue = list(answers)

    async def prompt(_p: str) -> str:
        return queue.pop(0) if queue else ""
    return prompt


def test_l3_downgrade_in_non_tty():
    """HARD: 非 TTY 请求 L3 → 自动降级 L1 并报备。"""
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, requested_level=3)
    assert gate.current_level() == 1
    assert "L2/L3" in gate.downgrade_notice


def test_l3_full_confirm_flow_unlocks():
    gate = ScanGate("example.com", batch_mode=False, is_tty=True,
                    prompt_fn=_canned(["CONFIRM 3", "example.com", "I UNDERSTAND AND AUTHORIZE"]),
                    requested_level=0)
    for step in (1, 2, 3):
        granted, _ = asyncio.run(gate.request_level_3_step(step, plan="L3 测试计划"))
        assert granted, f"step {step} 未通过"
    assert gate.current_level() == 3
    assert gate.verify_signature()
    assert gate.sig_path and gate.sig_path.exists()


def test_l3_wrong_code_rejected():
    gate = ScanGate("example.com", batch_mode=False, is_tty=True,
                    prompt_fn=_canned(["yes"]),  # 通用词无效
                    requested_level=0)
    granted, _ = asyncio.run(gate.request_level_3_step(1))
    assert not granted and gate.current_level() == 0


def test_l3_abort_reverts_to_l0():
    gate = ScanGate("example.com", batch_mode=False, is_tty=True,
                    prompt_fn=_canned(["abort"]), requested_level=0)
    granted, _ = asyncio.run(gate.request_level_3_step(1))
    assert not granted and gate.current_level() == 0 and gate.verify_signature() is False


def test_l2_signature_rejected_for_l3_unlock():
    """签名级别字段校验：L3 解锁后 verify 必须匹配 level=3。"""
    gate = ScanGate("example.com", batch_mode=False, is_tty=True,
                    prompt_fn=_canned(["CONFIRM 3", "example.com", "I UNDERSTAND AND AUTHORIZE"]),
                    requested_level=0)
    for step in (1, 2, 3):
        asyncio.run(gate.request_level_3_step(step))
    import json
    data = json.loads(gate.sig_path.read_text(encoding="utf-8"))
    assert data.get("level") == 3
    assert gate.verify_signature()


def test_l3_tool_blocked_without_unlock():
    """min_level=3 工具未解锁 → 注册表拒绝（五道守卫链）。"""
    settings = get_settings()
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, requested_level=0)
    registry = build_default(settings, gate, "example.com")
    result = asyncio.run(registry.execute(NormalizedToolCall(
        id="t1", name="dns_enum", arguments={"target": "sub.example.com"})))
    assert not result.success and "[门控]" in result.error


def test_l3_per_step_confirm_level_in_prompt():
    """逐项确认：L3 工具提示级别=3，tier1 工具带 tier 标注。"""
    seen: list[str] = []

    async def capture(prompt: str) -> str:
        seen.append(prompt)
        return "yes"

    gate = ScanGate("example.com", batch_mode=False, is_tty=True,
                    prompt_fn=capture, requested_level=0)
    gate.unlock_level_3()
    ok = asyncio.run(gate.confirm_step("dns_enum", "dns_enum sub.example.com", "高", level=3))
    assert ok and 'level="3"' in seen[-1]
    ok = asyncio.run(gate.confirm_step("nmap_scan_l3", "nmap -sS t", "高", level=3, tier=1))
    assert ok and 'tier="1"' in seen[-1] and "低强度模式" in seen[-1]


def test_enforce_stealth_level_tier1_allowlist():
    from security.stealth import enforce_stealth_level
    s = get_settings()
    # tier1: -sS 放行、-T4 剔除、--max-rate 被上限覆盖、强度钳制
    out, corrections = enforce_stealth_level(
        "nmap", ["nmap", "-sS", "-T4", "--max-rate", "999", "--version-intensity", "5", "t"],
        s, level=3, tier1=True)
    joined = " ".join(out)
    assert "-sS" in joined
    assert "-T4" not in joined
    assert str(s.L3_SYNSCAN_MAX_RATE) in joined and "999" not in joined
    assert "--version-intensity 2" in joined  # 5 → 2
    assert "--max-parallelism 1" in joined


def test_enforce_stealth_l2_unchanged():
    """L0-L2 行为逐字节不变：-sS 仍被剔、-sT 注入。"""
    from security.stealth import enforce_stealth
    s = get_settings()
    out, corrections = enforce_stealth("nmap", ["nmap", "-sS", "-p", "80", "t"], s)
    joined = " ".join(out)
    assert "-sS" not in joined and "-sT" in joined and "--max-rate 1" in joined
