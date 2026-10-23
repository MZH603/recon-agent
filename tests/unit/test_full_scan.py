"""级联扫描（full_scan）的门控与状态测试。"""
import asyncio
import json

from scripts.full_scan import load_state, make_cascade_gate, save_state


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


def test_load_state_per_target_file(tmp_path, monkeypatch):
    """状态按目标分文件存储（HARD：消除跨目标污染）。"""
    import scripts.full_scan as fs

    state_path = tmp_path / "reports" / "scan_state_example_com.json"
    monkeypatch.setattr(fs, "_state_path", lambda _t: state_path)
    state_path.parent.mkdir(parents=True)
    payload = {"deep_cards": [{"host": "a.example.com", "tech": {}}],
               "dir_results": [{"target": "a.example.com", "success": True, "data": {}}],
               "port_map": {"a.example.com": [80, 443]}}
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    state = load_state("example.com")
    assert state["done"] == {"a.example.com"} and len(state["deep_cards"]) == 1
    assert len(state["dir_results"]) == 1
    assert state["port_map"] == {"a.example.com": [80, 443]}


def test_load_state_does_not_mark_failed_l2_items_complete(tmp_path, monkeypatch):
    import scripts.full_scan as fs

    state_path = tmp_path / "reports" / "scan_state_example_com.json"
    monkeypatch.setattr(fs, "_state_path", lambda _t: state_path)
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps({
        "deep_cards": [
            {"host": "good.example.com", "tech": {}},
            {"host": "failed.example.com", "error": "aborted"},
        ],
        "dir_results": [
            {"target": "good.example.com", "success": True, "data": {}},
            {"target": "failed.example.com", "success": False, "error": "aborted"},
        ],
        "port_map": {},
    }), encoding="utf-8")

    state = load_state("example.com")

    assert state["done"] == {"good.example.com"}
    assert [card["host"] for card in state["deep_cards"]] == ["good.example.com"]
    assert [result["target"] for result in state["dir_results"]] == ["good.example.com"]


def test_save_state_merge_semantics(tmp_path, monkeypatch):
    """save_state 读-改-写合并（HARD：不覆盖既有键——历史数据丢失均源于全量覆盖写）。"""
    import scripts.full_scan as fs

    state_path = tmp_path / "reports" / "scan_state_example_com.json"
    monkeypatch.setattr(fs, "_state_path", lambda _t: state_path)
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps({"subdomains": ["a.example.com"]}), encoding="utf-8")

    save_state("example.com", {"deep_cards": [{"host": "b.example.com", "tech": {}}],
                               "dir_results": [], "port_map": {},
                               "subdomains": ["a.example.com"], "alive": ["a.example.com"]})
    merged = json.loads(state_path.read_text(encoding="utf-8"))
    assert merged["subdomains"] == ["a.example.com"]          # 既有键保留
    assert merged["deep_cards"] == [{"host": "b.example.com", "tech": {}}]  # 新键写入


def test_l0_failure_stops_instead_of_falling_back_to_root():
    from model.base import NormalizedToolCall
    from scripts.full_scan import stage_l0
    from tools.base import ToolResult

    class FailedRegistry:
        async def execute(self, call: NormalizedToolCall):
            return ToolResult.err(call.name, "enumeration timed out")

    result = asyncio.run(stage_l0("example.com", FailedRegistry(), None, None))

    assert result is None


def test_l2_abort_stops_remaining_hosts(tmp_path, monkeypatch):
    import scripts.full_scan as fs
    from scripts.full_scan import stage_l2
    from tools.base import ToolResult

    class Gate:
        level = 2

        def current_level(self):
            return self.level

    gate = Gate()

    class Registry:
        calls = 0

        async def execute(self, call):
            self.calls += 1
            gate.level = 0
            return ToolResult.err(call.name, "[门控] 用户中止")

    class Builder:
        data = type("Data", (), {"tech_cards": []})()

        def add_tech_card(self, card):
            self.data.tech_cards.append(card)

    registry = Registry()
    monkeypatch.setattr(fs, "save_state", lambda *_args: None)
    state = {"deep_cards": [], "dir_results": []}

    asyncio.run(stage_l2(
        "example.com", ["a.example.com", "b.example.com"], registry, Builder(),
        state, set(), gate,
    ))

    assert registry.calls == 1
