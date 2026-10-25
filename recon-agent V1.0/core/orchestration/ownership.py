"""Exclusive OS-backed ownership for one canonical SQLite session.

Lock files remain on disk; only the kernel lock conveys ownership. Process death
releases it automatically, without a timeout or stale-file takeover.
"""
from __future__ import annotations

import errno
import hashlib
import os
import tempfile
from pathlib import Path


class SessionOwnership:
    def __init__(self, db_path: Path, session_id: str):
        canonical = os.path.normcase(str(db_path.resolve()))
        digest = hashlib.sha256((canonical + '\0' + session_id).encode('utf-8')).hexdigest()
        # Use system temp directory for lock files to avoid permission issues on Windows
        lock_dir = Path(tempfile.gettempdir()) / 'recon-agent-locks'
        self.path = lock_dir / f'{digest}.lock'
        self.session_id = session_id
        self.handle = None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Use 'wb' binary mode for lock file to avoid Windows text-mode encoding issues.
        handle = None
        try:
            handle = self.path.open('wb')
            handle.write(b'\0')
            handle.flush()
            handle.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, PermissionError) as exc:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            if isinstance(exc, OSError) and exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise ValueError(f'Session {self.session_id} already has an active owner') from exc
            if isinstance(exc, PermissionError):
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
