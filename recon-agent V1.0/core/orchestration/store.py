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
                used_tokens INTEGER NOT NULL DEFAULT 0, used_cost REAL NOT NULL DEFAULT 0,
                cost_unknown_calls INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS task_usage (
                session_id TEXT NOT NULL, task_id TEXT NOT NULL,
                used_tokens INTEGER NOT NULL DEFAULT 0, used_cost REAL NOT NULL DEFAULT 0,
                cost_unknown_calls INTEGER NOT NULL DEFAULT 0, usage_estimated_calls INTEGER NOT NULL DEFAULT 0,
                max_tokens INTEGER NOT NULL, max_cost REAL NOT NULL,
                PRIMARY KEY(session_id,task_id));
            CREATE TABLE IF NOT EXISTS task_archive (
                session_id TEXT NOT NULL, task_id TEXT NOT NULL, state TEXT NOT NULL,
                PRIMARY KEY(session_id,task_id));
            CREATE TABLE IF NOT EXISTS session_event (
                session_id TEXT NOT NULL, event_id TEXT NOT NULL, timestamp TEXT NOT NULL,
                payload TEXT NOT NULL, PRIMARY KEY(session_id,event_id));
        ''')
        # Different sessions share this database; serialize legacy schema migration.
        await self.connection.execute('BEGIN IMMEDIATE')
        async with self.connection.execute('PRAGMA table_info(session_execution)') as cursor:
            columns = [row[1] for row in await cursor.fetchall()]
        if 'task_id' not in columns:
            await self.connection.execute("ALTER TABLE session_execution ADD COLUMN task_id TEXT NOT NULL DEFAULT ''")
        async with self.connection.execute("PRAGMA table_info(session_usage)") as cursor:
            usage_columns = [row[1] for row in await cursor.fetchall()]
        if "cost_unknown_calls" not in usage_columns:
            await self.connection.execute("ALTER TABLE session_usage ADD COLUMN cost_unknown_calls INTEGER NOT NULL DEFAULT 0")
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

    async def lookup(self, session_id: str, execution_id: str, name: str, arguments: dict, task_id: str = '',
                     *, reuse_completed: bool = True, authorized_retry: bool = False):
        async with self.connection.execute(
            'SELECT execution_id,status,result,task_id FROM session_execution WHERE session_id=? '
            "AND (execution_id=? OR signature=?) ORDER BY rowid DESC",
            (session_id, execution_id, signature(name, arguments))) as cursor:
            rows = await cursor.fetchall()
        # A checkpoint replay can reuse its own known result without issuing an
        # action again. Permission for a new retry never clears prior diagnostics.
        for key, status, result, recorded_task in rows:
            if key == execution_id and status == 'completed':
                full = json.loads(result) if result else None
                if full and not full.get('outcome_unknown'):
                    return {'execution_id': key, 'status': status, 'result': full}
        # An uncertain identical attempt takes precedence over earlier successful results.
        for key, status, result, recorded_task in rows:
            if authorized_retry and key != execution_id:
                continue
            full = json.loads(result) if result else None
            if full and full.get('outcome_unknown'):
                return {'execution_id': key, 'status': 'started', 'result': full}
            if status == 'started':
                return {'execution_id': key, 'status': status, 'result': full}
        for key, status, result, recorded_task in rows:
            if key == execution_id:
                return {'execution_id': key, 'status': status, 'result': json.loads(result) if result else None}
        if not reuse_completed or authorized_retry:
            return None
        for key, status, result, recorded_task in rows:
            full = json.loads(result) if result else None
            if full and full.get('success') and recorded_task == task_id:
                return {'execution_id': key, 'status': status, 'result': full}
        return None

    async def action_count(self, session_id: str) -> int:
        async with self.connection.execute(
            'SELECT COUNT(*) FROM session_execution WHERE session_id=?', (session_id,)) as cursor:
            return (await cursor.fetchone())[0]

    async def usage(self, session_id: str) -> dict:
        async with self.connection.execute(
            'SELECT decisions,used_tokens,used_cost,cost_unknown_calls FROM session_usage WHERE session_id=?',
            (session_id,)) as cursor:
            row = await cursor.fetchone()
        return dict(zip(('decisions', 'used_tokens', 'used_cost', 'cost_unknown_calls'), row or (0, 0, 0.0, 0)))

    async def save_usage(self, session_id: str, decisions: int, used_tokens: int, used_cost: float, cost_unknown_calls: int = 0):
        await self.connection.execute(
            'INSERT INTO session_usage (session_id,decisions,used_tokens,used_cost,cost_unknown_calls) VALUES (?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET '
            'decisions=MAX(decisions,excluded.decisions), used_tokens=MAX(used_tokens,excluded.used_tokens), '
            'used_cost=MAX(used_cost,excluded.used_cost), cost_unknown_calls=MAX(cost_unknown_calls,excluded.cost_unknown_calls)',
            (session_id, decisions, used_tokens, used_cost, cost_unknown_calls))
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


    async def task_usage(self, session_id: str, task_id: str) -> dict | None:
        async with self.connection.execute(
            'SELECT used_tokens,used_cost,cost_unknown_calls,usage_estimated_calls,max_tokens,max_cost '
            'FROM task_usage WHERE session_id=? AND task_id=?', (session_id, task_id)) as cursor:
            row = await cursor.fetchone()
        return dict(zip(('used_tokens', 'used_cost', 'cost_unknown_calls', 'usage_estimated_calls',
                         'max_tokens', 'max_cost'), row)) if row else None

    async def ensure_task(self, session_id: str, task_id: str, state: dict,
                          max_tokens: int, max_cost: float, *, fresh=False):
        # Bind legacy session totals exactly once; a /new task always starts empty.
        await self.connection.execute('BEGIN IMMEDIATE')
        try:
            async with self.connection.execute('SELECT COUNT(*) FROM task_usage WHERE session_id=?',
                                               (session_id,)) as cursor:
                existing = (await cursor.fetchone())[0]
            legacy = await self.usage(session_id) if not existing and not fresh else {}
            values = [max(state.get(key, 0), legacy.get(key, 0)) if not fresh else 0
                      for key in ('used_tokens', 'used_cost', 'cost_unknown_calls', 'usage_estimated_calls')]
            await self.connection.execute('INSERT OR IGNORE INTO task_usage VALUES (?,?,?,?,?,?,?,?)',
                (session_id, task_id, *values, state.get('max_tokens', max_tokens), state.get('max_cost', max_cost)))
            if not existing and not fresh:
                await self.connection.execute('INSERT INTO session_usage(session_id,decisions,used_tokens,used_cost,cost_unknown_calls) '
                    'VALUES(?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET '
                    'decisions=MAX(decisions,excluded.decisions),used_tokens=MAX(used_tokens,excluded.used_tokens), '
                    'used_cost=MAX(used_cost,excluded.used_cost),cost_unknown_calls=MAX(cost_unknown_calls,excluded.cost_unknown_calls)',
                    (session_id, max(state.get('decisions', 0), legacy.get('decisions', 0)), *values[:3]))
                await self.connection.execute("UPDATE session_execution SET task_id=? WHERE session_id=? AND task_id=''",
                                              (task_id, session_id))
            await self.connection.commit()
        except BaseException:
            await self.connection.rollback()
            raise
        return await self.task_usage(session_id, task_id)

    async def save_task_usage(self, session_id: str, task_id: str, decisions: int,
                              used_tokens: int, used_cost: float, cost_unknown_calls: int,
                              usage_estimated_calls: int):
        # One transaction makes journal recovery and session totals idempotent.
        await self.connection.execute('BEGIN IMMEDIATE')
        try:
            old = await self.task_usage(session_id, task_id)
            keys = ('used_tokens', 'used_cost', 'cost_unknown_calls', 'usage_estimated_calls')
            values = [max(old[key], value) for key, value in zip(keys,
                      (used_tokens, used_cost, cost_unknown_calls, usage_estimated_calls))]
            await self.connection.execute('UPDATE task_usage SET used_tokens=?,used_cost=?,cost_unknown_calls=?,usage_estimated_calls=? '
                                          'WHERE session_id=? AND task_id=?', (*values, session_id, task_id))
            await self.connection.execute('INSERT INTO session_usage(session_id,decisions,used_tokens,used_cost,cost_unknown_calls) '
                'VALUES(?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET decisions=MAX(decisions,excluded.decisions), '
                'used_tokens=used_tokens+excluded.used_tokens, used_cost=used_cost+excluded.used_cost, '
                'cost_unknown_calls=cost_unknown_calls+excluded.cost_unknown_calls',
                (session_id, decisions, values[0]-old['used_tokens'], values[1]-old['used_cost'],
                 values[2]-old['cost_unknown_calls']))
            await self.connection.commit()
        except BaseException:
            await self.connection.rollback()
            raise

    async def add_budget(self, session_id: str, task_id: str, tokens: int, cost: float):
        await self.connection.execute('UPDATE task_usage SET max_tokens=max_tokens+?,max_cost=max_cost+? '
                                      'WHERE session_id=? AND task_id=?', (tokens, cost, session_id, task_id))
        await self.connection.commit()

    async def archive_task(self, session_id: str, task_id: str, state: dict):
        await self.connection.execute('INSERT OR REPLACE INTO task_archive VALUES(?,?,?)',
                                     (session_id, task_id, json.dumps(state, ensure_ascii=False)))
        await self.connection.commit()
