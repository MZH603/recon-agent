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


def _resolve_addresses_blocking(host, port, anonymity):
    """阻塞解析（子进程执行）：DoH 启用时优先（HARD：完整匿名配置随参数传入，
    子进程不重读 config.yaml —— 防止 CLI 临时开关/内存覆盖在子进程中失效）。"""
    from security.anonymity.dns_privacy import resolve_host
    return resolve_host(host, port, config=anonymity)


async def resolve_addresses(host, port):
    try:
        ipaddress.ip_address(host)
    except ValueError:
        from utils.config import get_settings
        anonymity = get_settings().anonymity
        return await run_sync(_resolve_addresses_blocking, host, port, anonymity)
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
