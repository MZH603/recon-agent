"""A separately committed execution journal bridges tool execution and checkpoints."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4

import aiosqlite


def signature(name: str, arguments: dict) -> str:
    encoded = json.dumps([name, {k: v for k, v in arguments.items() if not k.startswith('_')}],
                         sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(encoded.encode()).hexdigest()


class SessionStore:
    def __init__(self, path: Path):
        self.path = path
        self.connection = None

    async def open(self):
        self.connection = await aiosqlite.connect(str(self.path))
        await self.connection.execute('PRAGMA busy_timeout=5000')
        await self.connection.executescript('''
            CREATE TABLE IF NOT EXISTS session_execution (
                session_id TEXT NOT NULL, execution_id TEXT NOT NULL,
                signature TEXT NOT NULL, name TEXT NOT NULL, arguments TEXT NOT NULL,
                status TEXT NOT NULL, result TEXT, task_id TEXT NOT NULL DEFAULT '', PRIMARY KEY(session_id, execution_id));
            CREATE INDEX IF NOT EXISTS session_execution_signature
                ON session_execution(session_id, signature);
            CREATE TABLE IF NOT EXISTS session_usage (
                session_id TEXT PRIMARY KEY, decisions INTEGER NOT NULL DEFAULT 0,
                used_tokens INTEGER NOT NULL DEFAULT 0, used_cost REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS session_event (
                session_id TEXT NOT NULL, event_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                payload TEXT NOT NULL, PRIMARY KEY(session_id,event_id));
        ''')
        async with self.connection.execute('PRAGMA table_info(session_execution)') as cursor:
            columns = [row[1] for row in await cursor.fetchall()]
        if 'task_id' not in columns:
            await self.connection.execute("ALTER TABLE session_execution ADD COLUMN task_id TEXT NOT NULL DEFAULT ''")
        await self.connection.commit()
        return self

    async def close(self):
        if self.connection is not None:
            await self.connection.close()
            self.connection = None

    async def start(self, session_id: str, execution_id: str, name: str, arguments: dict, task_id: str = ''):
        await self.connection.execute(
            'INSERT INTO session_execution (session_id,execution_id,signature,name,arguments,status,result,task_id) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)',
            (session_id, execution_id, signature(name, arguments), name,
             json.dumps(arguments, ensure_ascii=False), 'started', task_id))
        await self.connection.commit()

    async def complete(self, session_id: str, execution_id: str, result: dict):
        await self.connection.execute(
            'UPDATE session_execution SET status=?, result=? WHERE session_id=? AND execution_id=?',
            ('completed', json.dumps(result, ensure_ascii=False), session_id, execution_id))
        await self.connection.commit()

    async def lookup(self, session_id: str, execution_id: str, name: str, arguments: dict, task_id: str = ''):
        async with self.connection.execute(
            'SELECT execution_id,status,result FROM session_execution WHERE session_id=? '
            "AND (execution_id=? OR (signature=? AND (status='started' OR task_id IN (?,'')))) ORDER BY rowid DESC",
            (session_id, execution_id, signature(name, arguments), task_id)) as cursor:
            rows = await cursor.fetchall()
        # An uncertain identical attempt takes precedence over earlier successful results.
        for key, status, result in rows:
            if key == execution_id or status == 'started':
                return {'execution_id': key, 'status': status,
                        'result': json.loads(result) if result else None}
        for key, status, result in rows:
            full = json.loads(result) if result else None
            if full and full.get('success'):
                return {'execution_id': key, 'status': status, 'result': full}
        return None

    async def action_count(self, session_id: str) -> int:
        async with self.connection.execute(
            'SELECT COUNT(*) FROM session_execution WHERE session_id=?', (session_id,)) as cursor:
            return (await cursor.fetchone())[0]

    async def usage(self, session_id: str) -> dict:
        async with self.connection.execute(
            'SELECT decisions,used_tokens,used_cost FROM session_usage WHERE session_id=?',
            (session_id,)) as cursor:
            row = await cursor.fetchone()
        return dict(zip(('decisions', 'used_tokens', 'used_cost'), row or (0, 0, 0.0)))

    async def save_usage(self, session_id: str, decisions: int, used_tokens: int, used_cost: float):
        await self.connection.execute(
            'INSERT INTO session_usage VALUES (?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET '
            'decisions=MAX(decisions,excluded.decisions), used_tokens=MAX(used_tokens,excluded.used_tokens), '
            'used_cost=MAX(used_cost,excluded.used_cost)',
            (session_id, decisions, used_tokens, used_cost))
        await self.connection.commit()

    async def record_event(self, session_id: str, pending: dict):
        await self.connection.execute(
            'INSERT OR IGNORE INTO session_event VALUES (?,?,?,?)',
            (session_id, pending.get('event_id') or uuid4().hex,
             datetime.now(timezone.utc).isoformat(), json.dumps(pending, ensure_ascii=False)))
        await self.connection.commit()

    async def events(self, session_id: str) -> list[dict]:
        async with self.connection.execute(
            'SELECT timestamp,payload FROM session_event WHERE session_id=? ORDER BY rowid',
            (session_id,)) as cursor:
            return [{**json.loads(payload), 'timestamp': timestamp}
                    for timestamp, payload in await cursor.fetchall()]

    async def executions(self, session_id: str) -> list[dict]:
        async with self.connection.execute(
            'SELECT execution_id,task_id,name,arguments,status,result FROM session_execution '
            'WHERE session_id=? ORDER BY rowid', (session_id,)) as cursor:
            rows = await cursor.fetchall()
        executions = []
        for execution_id, task_id, name, arguments, status, result in rows:
            arguments = json.loads(arguments)
            executions.append({'execution_id': execution_id, 'task_id': task_id, 'name': name,
                'arguments': arguments, 'target': arguments.get('target'),
                'status': 'uncertain' if status == 'started' else status,
                'journal_status': status, 'result': json.loads(result) if result else None})
        return executions
