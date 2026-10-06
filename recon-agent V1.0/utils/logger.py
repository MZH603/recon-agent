"""Rich 控制台日志 + 审计落盘（HARD：审计带哈希链防篡改，主动操作全量留痕）。"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

from platforms.paths import get_config_dir
from rich.console import Console

_stderr_mode = False
_console: Console | None = None

_AUDIT_PATH = get_config_dir() / "audit.log"


def set_stderr_mode() -> None:
    """MCP stdio 模式：协议独占 stdout，日志全部转 stderr（HARD：防协议帧污染）。"""
    global _stderr_mode, _console
    _stderr_mode = True
    _console = None  # 下次输出时按当前 sys.stderr 重建


def configure_audit(path: Path) -> None:
    """重定向审计文件（测试/多任务隔离用）；哈希链在新文件上重新起链。"""
    global _AUDIT_PATH
    _AUDIT_PATH = Path(path)


def _chain_head() -> str:
    """每次写前实时读取文件尾哈希（HARD：不用缓存——多进程交错下保持链连续）。

    性能：只读文件末尾 4KB（而非全文件），追加成本 O(1)。
    """
    try:
        if not _AUDIT_PATH.exists():
            return ""
        with open(_AUDIT_PATH, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 4096))
            tail = f.read().decode("utf-8", errors="replace")
        lines = [line for line in tail.splitlines() if line.strip()]
        if not lines:
            return ""
        return str(json.loads(lines[-1]).get("hash", ""))
    except (OSError, json.JSONDecodeError):
        return ""


def audit(event: str, payload: dict | None = None) -> None:
    """审计日志（JSONL + 哈希链，HARD：防篡改可验证；失败时提示但不静默吞掉）。"""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "event": event,
        "payload": payload or {},
        "prev": _chain_head(),
    }
    digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    record["hash"] = digest
    try:
        _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_AUDIT_PATH, "a", encoding="utf-8", newline="") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        warn(f"审计日志写入失败（{exc}），事件: {event}")


def verify_audit_chain(path: Path | None = None) -> tuple[bool, int, str]:
    """校验审计哈希链完整性（HARD：任一记录被篡改/删除即失败）。"""
    target = Path(path) if path else _AUDIT_PATH
    if not target.exists():
        return True, 0, "审计文件不存在（尚无记录）"
    prev = ""
    count = 0
    try:
        lines = target.read_text(encoding="utf-8").strip().splitlines()
    except OSError as exc:
        return False, 0, f"读取失败: {exc}"
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, count, f"第 {index + 1} 行非 JSON"
        if "hash" not in record:
            prev = ""  # 旧格式记录：作为新的链基线
            continue
        body = {k: v for k, v in record.items() if k != "hash"}
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if digest != record["hash"]:
            return False, count, f"第 {count + 1} 条记录哈希不匹配（疑似篡改）"
        if record.get("prev", "") != prev:
            return False, count, f"第 {count + 1} 条记录链断裂（疑似删除）"
        prev = record["hash"]
        count += 1
    return True, count, "ok"


def console() -> Console:
    """自愈式获取 Console：底层流被关闭/替换时自动重建（跨测试/长会话健壮）。"""
    global _console
    current = _console.file if _console else None
    if _console is None or getattr(current, "closed", False):
        _console = Console(file=sys.stderr if _stderr_mode else None,
                           highlight=False, soft_wrap=False)
    return _console


def info(msg: str) -> None:
    """普通进度：[*] 前缀。"""
    console().print(f"[*] {msg}")


def ok(msg: str) -> None:
    """成功发现：[+] 前缀。"""
    console().print(f"[green][+][/green] {msg}")


def warn(msg: str) -> None:
    """警告/门控提示：[!] 前缀。"""
    console().print(f"[yellow][!][/yellow] {msg}")


def err(msg: str) -> None:
    """失败/降级：[-] 前缀。"""
    console().print(f"[red][-][/red] {msg}")


def section(title: str) -> None:
    """输出分节标题线。"""
    console().rule(title)


def audit_path() -> Path:
    """返回审计日志路径（供报告引用）。"""
    return _AUDIT_PATH
