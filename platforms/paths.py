"""跨平台目录解析（HARD：所有路径一律 pathlib，禁止手写 / 或 \\ 拼接）。

文档规定的目录名为 platform/，但该名字会遮蔽 Python 标准库 platform 模块，
因此实现上改名为 platforms/（业务代码中仍统一从这里取平台差异）。
"""
from __future__ import annotations

import os
import platform
from pathlib import Path


def _base(sub: str) -> Path:
    """按平台解析 recon-agent 基础目录。"""
    if platform.system() == "Windows":
        base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
    else:
        base = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    return Path(base) / "recon-agent" / sub


def get_config_dir() -> Path:
    """配置目录：Windows %APPDATA%\\recon-agent；Linux ~/.config/recon-agent。"""
    return _base("")


def get_cache_dir() -> Path:
    """缓存目录（SQLite 语义缓存 + 工具原始输出落盘）。"""
    return _base("cache")


def get_auth_dir() -> Path:
    """签名文件目录（HARD：L2 三级确认后生成 auth/<target>.sig）。"""
    return _base("auth")


def get_cve_dir() -> Path:
    """CVE 知识库签名快照目录。"""
    return _base("cve_snapshot")


def get_output_dir() -> Path:
    """报告输出目录：当前工作目录下 reports/（pathlib 自动适配分隔符）。"""
    out = Path.cwd() / "reports"
    out.mkdir(parents=True, exist_ok=True)
    return out
