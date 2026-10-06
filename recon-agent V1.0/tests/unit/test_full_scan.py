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
