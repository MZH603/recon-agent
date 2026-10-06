"""级联扫描（full_scan）的门控与状态测试。"""
import asyncio
import json

from scripts.full_scan import load_deep_state, make_cascade_gate


def test_cascade_gate_level1_is_immediately_active():
    """level=1 显式声明即生效（L1 一次确认语义：启动参数即确认）。"""
    gate = make_cascade_gate("example.com", level=1, auto_confirm=True)
    assert gate.current_level() == 1


def test_cascade_gate_level2_requires_unlock():
    """level=2 初始被压到 L1，必须走三次解锁（HARD）。"""
    gate = make_cascade_gate("example.com", level=2, auto_confirm=True)
    assert gate.current_level() == 1
    ok1, _ = asyncio.run(gate.request_level_2_step(1))
    assert ok1
    ok2, _ = asyncio.run(gate.request_level_2_step(2))
    assert ok2
    ok3, _ = asyncio.run(gate.request_level_2_step(3))
    assert ok3 and gate.current_level() == 2 and gate.verify_signature()


def test_load_deep_state_interops_with_fleet_state(tmp_path):
    """与 fleet_l2 的状态文件互通（深度卡片复用，避免重复扫描）。"""
    import scripts.full_scan as fs

    fleet = tmp_path / "fleet_l2_state.json"
    payload = {"deep_cards": [{"host": "a.example.com", "tech": {}}],
               "dir_results": [{"target": "a.example.com", "success": True, "data": {}}]}
    fleet.write_text(json.dumps(payload), encoding="utf-8")
    old = fs.FLEET_STATE
    fs.FLEET_STATE = fleet
    try:
        state = fs.load_deep_state()
        assert state["done"] == {"a.example.com"} and len(state["deep_cards"]) == 1
        assert len(state["dir_results"]) == 1
    finally:
        fs.FLEET_STATE = old
