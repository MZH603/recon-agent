"""SQLite 语义缓存（HARD：精确哈希 key = hash(目标+工具+参数)，TTL 内直接复用）。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


def cache_key(target: str, tool: str, params: dict) -> str:
    """对 (目标, 工具, 参数) 计算稳定哈希（v1 仅精确去重，语义等价留待 v2）。"""
    raw = json.dumps({"t": target, "tool": tool, "p": params}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SQLiteCache:
    """极简 KV 缓存：key -> JSON 值 + 写入时间戳，按 TTL 判定失效。"""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT NOT NULL, ts REAL NOT NULL)"
        )
        self._conn.commit()

    def get(self, key: str, ttl: int) -> dict | None:
        """TTL 内命中返回缓存值，否则 None。"""
        row = self._conn.execute("SELECT v, ts FROM cache WHERE k = ?", (key,)).fetchone()
        if row is None:
            return None
        if time.time() - row[1] > ttl:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return None

    def put(self, key: str, value: dict) -> None:
        """写入/覆盖缓存项。"""
        self._conn.execute(
            "INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?, ?, ?)",
            (key, json.dumps(value, ensure_ascii=False), time.time()),
        )
        self._conn.commit()

    def close(self) -> None:
        """关闭连接。"""
        self._conn.close()
