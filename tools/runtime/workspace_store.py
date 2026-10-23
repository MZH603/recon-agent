"""Transactional records isolated by exact target and durable session identity."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from security.stealth import normalize_host
from tools.runtime.evidence_store import canonical_json

COLLECTIONS = ('notes', 'coverage', 'threat_models', 'findings')


class WorkspaceStore:
    def __init__(self, config, evidence, session_id):
        self.config = config
        self.evidence = evidence
        self.session_id = session_id
        self.used = False
        self.root = Path(config.directory) if config.directory else evidence.root / 'workspace'

    def _namespace(self, target):
        return hashlib.sha256(canonical_json([self.session_id, normalize_host(target).lower()])).hexdigest()

    def _connect(self):
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / 'records.sqlite3'
        if path.is_symlink():
            raise ValueError('workspace database symlink forbidden')
        connection = sqlite3.connect(path, timeout=5)
        connection.execute('CREATE TABLE IF NOT EXISTS records '
            '(namespace TEXT, collection TEXT, id TEXT, body TEXT, PRIMARY KEY(namespace, collection, id))')
        return connection

    def _snapshot(self, connection, namespace):
        result = {key: [] for key in COLLECTIONS}
        rows = connection.execute('SELECT collection, body FROM records WHERE namespace=? ORDER BY id', (namespace,))
        for collection, body in rows:
            result[collection].append(json.loads(body))
        return result

    def _validate(self, collection, body, target):
        for identifier in body.get('evidence_ids', []):
            self.evidence.get(identifier, target=target)
        if collection in ('notes', 'threat_models', 'findings'):
            if not body.get('title', '').strip() or not body.get('content', '').strip():
                raise ValueError('title and content are required')
        if collection == 'coverage' and (not body.get('surface', '').strip() or not body.get('risk_area', '').strip()):
            raise ValueError('surface and risk_area are required')
        if collection == 'findings' and not body.get('evidence_ids'):
            raise ValueError('findings require same-target evidence IDs')
        if collection == 'coverage' and body.get('outcome') == 'verified' and not body.get('evidence_ids'):
            raise ValueError('verified coverage requires same-target evidence IDs')

    def operate(self, target, collection, action, identifier=None, fields=None, limit=50):
        namespace = self._namespace(target)
        connection = self._connect()
        try:
            connection.execute('BEGIN IMMEDIATE')
            record = None
            if collection:
                if collection not in COLLECTIONS:
                    raise ValueError('unknown collection')
                if action in ('get', 'update', 'delete'):
                    if not identifier:
                        raise ValueError('record_id required')
                    row = connection.execute('SELECT body FROM records WHERE namespace=? AND collection=? AND id=?',
                        (namespace, collection, identifier)).fetchone()
                    if row is None:
                        raise ValueError('record not found in current target/session')
                    record = json.loads(row[0])
                if action in ('create', 'update'):
                    if action == 'create':
                        count = connection.execute('SELECT COUNT(*) FROM records WHERE namespace=?', (namespace,)).fetchone()[0]
                        if count >= self.config.max_records:
                            raise ValueError('workspace record limit reached')
                        record = {'id': uuid4().hex, 'revision': 0, 'created_at': datetime.now(timezone.utc).isoformat()}
                    record = {**record, **(fields or {})}
                    self._validate(collection, record, target)
                    record['revision'] += 1
                    record['updated_at'] = datetime.now(timezone.utc).isoformat()
                    connection.execute('INSERT OR REPLACE INTO records VALUES (?,?,?,?)',
                        (namespace, collection, record['id'], canonical_json(record).decode('utf-8')))
                elif action == 'delete':
                    connection.execute('DELETE FROM records WHERE namespace=? AND collection=? AND id=?',
                        (namespace, collection, identifier))
            snapshot = self._snapshot(connection, namespace)
            envelope = {'session_id': self.session_id, 'target': target, 'collection': collection,
                'action': action, 'record_id': record['id'] if record else None, 'workspace': snapshot}
            # Publish evidence before committing the mutation: failed evidence writes roll back.
            evidence_id = self.evidence.put(target, 'workspace_snapshot', envelope)
            evidence_record = self.evidence.get(evidence_id, target=target)
            connection.commit()
            data = {'session_id': self.session_id, 'target': target, 'workspace': snapshot,
                'snapshot_evidence_id': evidence_id}
            if record is not None:
                data['record'] = record
            if collection and action == 'list':
                data.update(records=snapshot[collection][:limit], total=len(snapshot[collection]))
            return data, evidence_record
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
