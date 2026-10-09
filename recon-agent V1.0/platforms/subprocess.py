"""Owned exec subprocesses, bounded tree cleanup, and retained partial streams."""
from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path


def _decode(raw) -> str:
    return bytes(raw or b'').decode('utf-8', errors='replace')


def _windows_job(pid):
    """A job survives parent exit and terminates descendants on handle close."""
    import ctypes as c
    from ctypes import wintypes as w
    class Basic(c.Structure):
        _fields_ = [('ProcessTime', c.c_int64), ('JobTime', c.c_int64),
                    ('Flags', w.DWORD), ('Min', c.c_size_t), ('Max', c.c_size_t),
                    ('Active', w.DWORD), ('Affinity', c.c_size_t),
                    ('Priority', w.DWORD), ('Scheduling', w.DWORD)]
    class IO(c.Structure):
        _fields_ = [(name, c.c_uint64) for name in ('read_ops','write_ops','other_ops','read_bytes','write_bytes','other_bytes')]
    class Extended(c.Structure):
        _fields_ = [('Basic', Basic), ('IO', IO), ('ProcessMemory', c.c_size_t),
                    ('JobMemory', c.c_size_t), ('PeakProcess', c.c_size_t), ('PeakJob', c.c_size_t)]
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    handle = kernel.OpenProcess(0x0100 | 0x0001, False, pid)
    info = Extended()
    info.Basic.Flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not job or not handle or not kernel.SetInformationJobObject(job, 9, c.byref(info), c.sizeof(info)) or not kernel.AssignProcessToJobObject(job, handle):
        if handle: kernel.CloseHandle(handle)
        if job: kernel.CloseHandle(job)
        return None
    kernel.CloseHandle(handle)
    return kernel, job


def release_process(proc):
    job = getattr(proc, '_recon_job', None)
    if job:
        proc._recon_job = None
        return bool(job[0].CloseHandle(job[1]))
    return False


def _resume_windows_process(pid):
    """Resume the initial thread only after it is contained by the Job."""
    import ctypes as c
    from ctypes import wintypes as w
    class ThreadEntry(c.Structure):
        _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('tid', w.DWORD),
                    ('pid', w.DWORD), ('base_priority', w.LONG),
                    ('delta_priority', w.LONG), ('flags', w.DWORD)]
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
    kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
    kernel.Thread32First.argtypes = [w.HANDLE, c.POINTER(ThreadEntry)]
    kernel.Thread32Next.argtypes = [w.HANDLE, c.POINTER(ThreadEntry)]
    kernel.OpenThread.restype = w.HANDLE
    kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.ResumeThread.argtypes = [w.HANDLE]
    kernel.ResumeThread.restype = w.DWORD
    kernel.CloseHandle.argtypes = [w.HANDLE]
    snapshot = kernel.CreateToolhelp32Snapshot(0x00000004, 0)
    if not snapshot or snapshot == c.c_void_p(-1).value:
        raise OSError('Cannot enumerate suspended process threads')
    try:
        entry = ThreadEntry()
        entry.size = c.sizeof(entry)
        found = kernel.Thread32First(snapshot, c.byref(entry))
        while found:
            if entry.pid == pid:
                thread = kernel.OpenThread(0x0002, False, entry.tid)
                if not thread: raise OSError('Cannot resume owned process')
                try:
                    if kernel.ResumeThread(thread) == 0xffffffff:
                        raise OSError('Cannot resume owned process')
                    return
                finally:
                    kernel.CloseHandle(thread)
            found = kernel.Thread32Next(snapshot, c.byref(entry))
        raise OSError('Owned suspended process has no initial thread')
    finally:
        kernel.CloseHandle(snapshot)


def _capture_cleanup(confirmed):
    from tools.runtime.execution_wait import partial_output
    captured = partial_output.get()
    if captured is not None:
        captured['cleanup_confirmed'] = captured.get('cleanup_confirmed', True) and confirmed


async def spawn_owned(*args, **kwargs):
    options = {'start_new_session': True} if os.name != 'nt' else {'creationflags': 0x08000000 | 0x00000004}
    async def spawn():
        proc = await asyncio.create_subprocess_exec(*args, **options, **kwargs)
        proc._recon_process_group = os.name != 'nt'
        proc._recon_job = _windows_job(proc.pid) if os.name == 'nt' else None
        if os.name == 'nt':
            try:
                if not proc._recon_job:
                    raise OSError('Cannot contain tool process in a Windows Job')
                _resume_windows_process(proc.pid)
            except Exception:
                await kill_and_reap(proc)
                raise
        return proc
    task = asyncio.create_task(spawn())
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        done, _ = await asyncio.wait({task}, timeout=2)
        if done:
            with contextlib.suppress(Exception):
                await kill_and_reap(task.result())
        else:
            _capture_cleanup(False)
            def late(created):
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    asyncio.create_task(kill_and_reap(created.result()))
            task.add_done_callback(late)
        raise


async def kill_and_reap(proc):
    """Return tree cleanup confirmation independently of coroutine cancellation."""
    confirmed = False
    if os.name == 'nt':
        confirmed = release_process(proc)
        if not confirmed:
            try:
                killer = await asyncio.create_subprocess_exec('taskkill','/PID',str(proc.pid),'/T','/F',
                    stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,
                    creationflags=0x08000000)
                done,_ = await asyncio.wait({asyncio.create_task(killer.wait())},timeout=1)
                if not done:
                    with contextlib.suppress(ProcessLookupError): killer.kill()
            except OSError:
                pass
    elif getattr(proc, '_recon_process_group', False):
        import signal
        try:
            os.killpg(proc.pid,signal.SIGKILL)
            confirmed = True
        except ProcessLookupError:
            confirmed = True
        except OSError:
            pass
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
    _capture_cleanup(confirmed)
    cleanup=asyncio.create_task(proc.wait())
    done,_=await asyncio.wait({cleanup},timeout=1)
    if not done:
        cleanup.cancel()
    transport=getattr(proc,'_transport',None)
    if transport: transport.close()
    return confirmed


async def kill_and_reap(proc):
    """Drain pipes and reap a cancelled tool before releasing the session owner."""
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
    await proc.communicate()


async def run_command(
    args: list[str],
    timeout: float = 30,
    input_data: str | None = None,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    """执行外部命令，返回 (exit_code, stdout, stderr)。

    - 仅 exec 数组形式，不经过 shell（HARD）；
    - 超时强制 kill 并返回码 124；
    - 启动错误收敛为错误返回值；取消先回收进程再向上抛。
    """
    try:
        proc = await spawn_owned(
            *[str(a) for a in args],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            cwd=str(cwd) if cwd else None,
        )
    except (OSError, ValueError, NotImplementedError) as exc:
        return 127, "", f"[spawn-failed] {exc}"
    captured = [bytearray(), bytearray()]
    async def drain(stream, index):
        while chunk := await stream.read(65536):
            captured[index].extend(chunk)
    async def feed():
        if input_data is not None:
            try:
                proc.stdin.write(input_data.encode('utf-8'))
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()
    tasks = [asyncio.create_task(drain(proc.stdout, 0)), asyncio.create_task(drain(proc.stderr, 1)),
             asyncio.create_task(feed()), asyncio.create_task(proc.wait())]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.ALL_COMPLETED)
        if pending:
            confirmed = await kill_and_reap(proc)
            return 124, _decode(captured[0]), _decode(captured[1]) + f'\n[timeout] 命令超过 {timeout:g}s；' + ('进程树已终止' if confirmed else '进程树停止未确认；outcome unknown')
        for task in done: task.result()
        return proc.returncode or 0, _decode(captured[0]), _decode(captured[1])
    except asyncio.CancelledError:
        from tools.runtime.execution_wait import partial_output
        partial = partial_output.get()
        if partial is not None:
            clean = partial.get('_redactor', lambda value: value)
            partial.update(clean({'stdout': _decode(captured[0]), 'stderr': _decode(captured[1])}))
        await kill_and_reap(proc)
        raise
    finally:
        for task in tasks:
            if not task.done(): task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        release_process(proc)
