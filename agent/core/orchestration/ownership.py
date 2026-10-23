"""Exclusive OS-backed ownership for one canonical SQLite session.

Lock files remain on disk; only the kernel lock conveys ownership. Process death
releases it automatically, without a timeout or stale-file takeover.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path


class SessionOwnership:
    def __init__(self, db_path: Path, session_id: str):
        canonical = os.path.normcase(str(db_path.resolve()))
        digest = hashlib.sha256((canonical + '\0' + session_id).encode('utf-8')).hexdigest()
        self.path = db_path.resolve().parent / '.session-locks' / f'{digest}.lock'
        self.session_id = session_id
        self.handle = None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open('a+b')
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b'\0')
                handle.flush()
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise ValueError(f'Session {self.session_id} already has an active owner') from exc
            raise
        self.handle = handle

    def release(self):
        if self.handle is None:
            return
        handle, self.handle = self.handle, None
        try:
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
