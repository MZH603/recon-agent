"""跨平台工具发现（HARD：Windows 同时探测 .exe/.bat/.cmd/.ps1；优先 venv 内工具）。"""
from __future__ import annotations

import platform
import shutil
import sys
from pathlib import Path

WIN_EXTS = (".exe", ".bat", ".cmd", ".ps1")


def find_tool(name: str) -> str | None:
    """在 PATH 与当前 venv 中查找可执行文件，返回绝对路径或 None。

    - Windows：依次尝试 name、name.exe、name.bat、name.cmd、name.ps1；
    - Linux：直接 which；
    - 额外探测当前 venv 的 Scripts/bin（避免要求用户先激活虚拟环境）。
    """
    exts = WIN_EXTS if platform.system() == "Windows" else ("",)
    for ext in exts:
        found = shutil.which(name + ext)
        if found:
            return found
    venv_bin = Path(sys.prefix) / ("Scripts" if platform.system() == "Windows" else "bin")
    for ext in exts:
        candidate = venv_bin / (name + ext)
        if candidate.exists():
            return str(candidate)
    return None
