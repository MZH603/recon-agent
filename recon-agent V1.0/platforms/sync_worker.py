"""Execute trusted, picklable blocking functions in a killable Python process."""
from __future__ import annotations

import asyncio
import contextlib
import pickle
import sys
import os
import socket
import ipaddress
from platforms.subprocess import spawn_owned, release_process


async def resolve_addresses(host, port):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return await run_sync(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    # A numeric address requires no name service or background resolver thread.
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST)


async def run_sync(function, *args, **kwargs):
    # Serialization occurs only for local trusted code, never model supplied code.
    request = pickle.dumps((function,args,kwargs))
    process = await spawn_owned(sys.executable,'-m','platforms.sync_worker',
        stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    try:
        raw, error = await process.communicate(request)
    except asyncio.CancelledError:
        from platforms.subprocess import kill_and_reap
        await kill_and_reap(process)
        raise
    finally:
        release_process(process)
    if process.returncode:
        raise OSError('同步工具工作进程失败：'+error.decode('utf-8',errors='replace')[:500])
    success, value = pickle.loads(raw)
    if not success:
        raise value
    return value


def main():
    function,args,kwargs = pickle.loads(sys.stdin.buffer.read())
    try:
        with contextlib.redirect_stdout(sys.stderr):
            value = function(*args,**kwargs)
        result = (True,value)
    except Exception as exc:
        result = (False,exc)
    sys.stdout.buffer.write(pickle.dumps(result))
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
