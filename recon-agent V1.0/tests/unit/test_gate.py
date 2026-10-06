"""三级门控契约测试（HARD：精确确认码 / batch 禁 L2 / 无 TTY 降级 / 会话隔离 / abort）。"""
import asyncio

from gate.scan_gate import ScanGate


def make_gate(inputs: list[str], **kw) -> ScanGate:
    """注入固定输入序列的假交互门。"""
    queue = list(inputs)

    async def fake_prompt(prompt: str) -> str:
        return queue.pop(0) if queue else ""

    return ScanGate("example.com", auth_dir=kw.pop("auth_dir"), prompt_fn=fake_prompt, **kw)


def test_l2_requires_three_distinct_exact_confirmations(tmp_path):
    gate = make_gate(["CONFIRM 2", "example.com", "I UNDERSTAND AND AUTHORIZE"], auth_dir=tmp_path)
    assert asyncio.run(gate.request_level_2_step(1))[0]
    assert asyncio.run(gate.request_level_2_step(2))[0]
    ok, _ = asyncio.run(gate.request_level_2_step(3))
    assert ok and gate.current_level() == 2
    assert gate.verify_signature()  # 签名文件已生成且校验通过


def test_simple_yes_does_not_count_as_confirmation(tmp_path):
    gate = make_gate(["yes"], auth_dir=tmp_path)
    ok, _ = asyncio.run(gate.request_level_2_step(1))
    assert not ok and gate.current_level() == 0  # 通用词无效


def test_target_string_must_match_exactly(tmp_path):
    gate = make_gate(["CONFIRM 2", "sub.example.com"], auth_dir=tmp_path)
    asyncio.run(gate.request_level_2_step(1))
    ok, _ = asyncio.run(gate.request_level_2_step(2))
    assert not ok  # 目标串不匹配 → 拒绝


def test_batch_mode_permanently_disables_l2(tmp_path):
    gate = make_gate(["CONFIRM 2", "example.com", "I UNDERSTAND AND AUTHORIZE"],
                     auth_dir=tmp_path, batch_mode=True)
    for step in (1, 2, 3):
        ok, _ = asyncio.run(gate.request_level_2_step(step))
        assert not ok
    assert gate.current_level() < 2


def test_level2_without_tty_auto_downgrades_to_level1(tmp_path):
    gate = make_gate([], auth_dir=tmp_path, is_tty=False, requested_level=2)
    assert gate.current_level() == 1
    assert "降级" in gate.downgrade_notice


def test_abort_returns_to_level_0(tmp_path):
    gate = make_gate(["CONFIRM 2", "example.com", "I UNDERSTAND AND AUTHORIZE"], auth_dir=tmp_path)
    for step in (1, 2, 3):
        asyncio.run(gate.request_level_2_step(step))
    gate.abort()
    assert gate.current_level() == 0
    assert not gate.verify_signature()


def test_gate_does_not_persist_across_sessions(tmp_path):
    first = make_gate(["CONFIRM 2", "example.com", "I UNDERSTAND AND AUTHORIZE"], auth_dir=tmp_path)
    for step in (1, 2, 3):
        asyncio.run(first.request_level_2_step(step))
    second = ScanGate("example.com", auth_dir=tmp_path, prompt_fn=lambda p: asyncio.sleep(0, result=""))  # 新会话
    assert second.current_level() == 0  # HARD: 不读取旧签名
    assert not second.verify_signature()


def test_l1_confirmation(tmp_path):
    gate = make_gate(["yes"], auth_dir=tmp_path)
    assert asyncio.run(gate.request_level_1("端口探测")) and gate.current_level() == 1
    gate2 = make_gate(["n"], auth_dir=tmp_path)
    assert not asyncio.run(gate2.request_level_1("端口探测")) and gate2.current_level() == 0
