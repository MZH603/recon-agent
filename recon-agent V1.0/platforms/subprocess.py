"""无 shell 子进程封装（HARD：一律 asyncio.create_subprocess_exec，禁止 os.system / shell=True）。"""
from __future__ import annotations

import asyncio
from pathlib import Path


def _decode(raw: bytes | None) -> str:
    """统一 UTF-8 解码，坏字节不炸。"""
    return (raw or b"").decode("utf-8", errors="replace")


async def run_command(
    args: list[str],
    timeout: int = 30,
    input_data: str | None = None,
    cwd: Path | None = None,
) -> tuple[int, str, str]:
    """执行外部命令，返回 (exit_code, stdout, stderr)。

    - 仅 exec 数组形式，不经过 shell（HARD）；
    - 超时强制 kill 并返回码 124；
    - 任何异常都收敛为错误返回值，不向上抛（分层错误处理）。
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *[str(a) for a in args],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data is not None else None,
            cwd=str(cwd) if cwd else None,
        )
    except (OSError, ValueError, NotImplementedError) as exc:
        return 127, "", f"[spawn-failed] {exc}"
    try:
        out, err = await asyncio.wait_for(
            proc.communicate(input_data.encode("utf-8") if input_data is not None else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "", f"[timeout] 命令超过 {timeout}s 已强制终止"
    return (proc.returncode or 0, _decode(out), _decode(err))
