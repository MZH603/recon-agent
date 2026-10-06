"""审计日志哈希链测试（P1-8：防篡改可验证）。"""
import json

from utils.logger import audit, configure_audit, verify_audit_chain


def test_audit_chain_valid_and_verifiable(tmp_path):
    path = tmp_path / "audit.log"
    configure_audit(path)
    for event in ("gate_init", "gate_confirm", "l2_unlocked"):
        audit(event, {"k": event})
    ok, count, msg = verify_audit_chain(path)
    assert ok and count == 3 and msg == "ok"


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.log"
    configure_audit(path)
    audit("event_a", {"v": 1})
    audit("event_b", {"v": 2})
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["payload"]["v"] = 999  # 篡改第一条记录内容
    lines[0] = json.dumps(tampered, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, _, msg = verify_audit_chain(path)
    assert not ok and "篡改" in msg


def test_audit_chain_detects_deletion(tmp_path):
    path = tmp_path / "audit.log"
    configure_audit(path)
    audit("event_a", {"v": 1})
    audit("event_b", {"v": 2})
    audit("event_c", {"v": 3})
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]  # 删除中间记录 → 链断裂
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, _, msg = verify_audit_chain(path)
    assert not ok and "断裂" in msg


def test_old_format_records_rebase_chain(tmp_path):
    """v1.0 旧格式（无 hash 字段）记录作为链基线，不报错。"""
    path = tmp_path / "audit.log"
    legacy = json.dumps({"ts": "t", "event": "legacy", "payload": {}})
    path.write_text(legacy + "\n", encoding="utf-8")
    configure_audit(path)
    audit("new_event", {"v": 1})
    ok, count, _ = verify_audit_chain(path)
    assert ok and count == 1
