"""痕迹清理机制（HARD：审计日志与 reports/ 永不清理；清理范围白名单制）。

清理范围（scope）：
- session    本会话工作产物：cache/task_* 原始输出落盘、evidence *.tmp 残留、
             临时登记文件（TempArtifactRegistry）、oneterm 会话临时目录；
- artifacts  证据与工作区（evidence/*.json、artifacts/、workspace records.sqlite3）
             —— 显式 opt-in（cleanup_keep_evidence=True 时 CLI 强制要求 --yes）；
- system     系统痕迹：本机 DNS 缓存刷新、auth/<target>.sig 授权签名文件、
             第三方工具遗留输出（tools/oneforall/results/）；
- all        以上全部。

保留清单（HARD 永不触碰）：
- audit.log（哈希链防篡改证据，报告完整性依赖）、reports/（交付物）、
  config.yaml / launcher.json / cve_snapshot/（配置与知识库）、
  agent_state.sqlite（会话恢复功能，非侦察痕迹）。
"""
from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

from utils.logger import audit

# ---- 清理白名单（HARD：逐项显式列出，禁止通配用户目录）----

_CACHE_SEGMENTS: tuple[str, ...] = ("task_",)          # cache/task_<id>/ 前缀
_EVIDENCE_TMP_SUFFIX: str = ".tmp"
_ARTIFACT_SEGMENTS: tuple[str, ...] = ("workspace", "artifacts")
_ONEFORALL_RESULTS: tuple[Path, ...] = ()              # 运行时按项目根解析
_AUTH_SEGMENT: str = "auth"

_DNS_FLUSH_COMMANDS: dict[str, tuple[str, ...]] = {
    "Windows": ("ipconfig", "/flushdns"),
    "Linux": ("resolvectl", "flush-caches"),
    "Darwin": ("dscacheutil", "-flushcache"),
}

_REGISTERED: list[Path] = []


class TempArtifactRegistry:
    """会话临时文件登记（工具运行时调用；cleanup(session) 时销毁）。"""

    @staticmethod
    def register(path: str | Path) -> Path:
        p = Path(path)
        _REGISTERED.append(p)
        return p

    @staticmethod
    def registered() -> list[Path]:
        return list(_REGISTERED)

    @staticmethod
    def clear() -> None:
        _REGISTERED.clear()


def _shred_delete(path: Path) -> bool:
    """单遍覆写后删除（HARD：SSD/COW 文件系统不承诺取证级，仅本地卫生）。

    返回 True=文件已删除；False=不存在或删除失败（不抛异常，逐项审计）。
    """
    try:
        if not path.exists():
            path.unlink(missing_ok=True)
            return True
        if path.is_file():
            try:
                size = path.stat().st_size
                with open(path, "r+b") as handle:
                    handle.write(b"\x00" * size)
                    handle.flush()
            except OSError:
                pass  # 覆写失败仍尝试删除（只读盘等场景）
            path.unlink(missing_ok=True)
            return not path.exists()
        shutil.rmtree(path, ignore_errors=True)
        return not path.exists()
    except OSError as exc:
        audit("trace_cleanup_failed", {"path": str(path)[:256], "error": str(exc)[:128]})
        return False


def _cache_dir() -> Path:
    from platforms.paths import get_cache_dir
    return get_cache_dir()


def _config_dir() -> Path:
    from platforms.paths import get_config_dir
    return get_config_dir()


def _evidence_root() -> Path:
    import os
    from tools.runtime.evidence_store import EvidenceStore
    return EvidenceStore().root


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _session_paths() -> list[Path]:
    """session 范围：缓存落盘 + 证据临时残留 + 登记文件。"""
    paths: list[Path] = []
    cache = _cache_dir()
    if cache.exists():
        for child in cache.iterdir():
            if child.is_dir() and any(child.name.startswith(seg) for seg in _CACHE_SEGMENTS):
                paths.append(child)
    evidence = _evidence_root()
    if evidence.exists():
        for child in evidence.iterdir():
            if child.name.startswith(".") and child.name.endswith(_EVIDENCE_TMP_SUFFIX):
                paths.append(child)
    paths.extend(p for p in _REGISTERED if p.exists())
    return paths


def _artifact_paths() -> list[Path]:
    """artifacts 范围：证据库 + 工作区 + 工具产物目录。"""
    paths: list[Path] = []
    evidence = _evidence_root()
    for seg in _ARTIFACT_SEGMENTS:
        child = evidence / seg
        if child.exists():
            paths.append(child)
    for child in evidence.glob("*.json"):
        paths.append(child)
    return paths


def _system_paths(target: str | None = None) -> list[Path]:
    """system 范围：授权签名文件（可选按 target 过滤）+ 第三方工具遗留输出。"""
    paths: list[Path] = []
    auth = _config_dir() / _AUTH_SEGMENT
    if auth.exists():
        if target:
            from security.stealth import normalize_host
            candidate = auth / f"{normalize_host(target).lower()}.sig"
            if candidate.exists():
                paths.append(candidate)
        else:
            paths.extend(auth.glob("*.sig"))
    legacy = _project_root() / "tools" / "oneforall" / "results"
    if legacy.exists():
        paths.append(legacy)
    return paths


def flush_local_dns_cache() -> bool:
    """刷新本机 DNS 缓存（防本地 resolver 缓存泄露已查询目标）。失败仅审计不抛。"""
    system = platform.system()
    command = _DNS_FLUSH_COMMANDS.get(system)
    if not command:
        audit("trace_cleanup_dns_flush_skipped", {"system": system})
        return False
    try:
        result = subprocess.run(command, capture_output=True, timeout=30, check=False)
        ok = result.returncode == 0
        audit("trace_cleanup_dns_flush", {"system": system, "ok": ok})
        return ok
    except (OSError, subprocess.TimeoutExpired) as exc:
        audit("trace_cleanup_dns_flush_failed", {"system": system, "error": str(exc)[:128]})
        return False


def cleanup(scope: str = "session", target: str | None = None) -> dict[str, int]:
    """执行痕迹清理，返回 {removed, failed}；全程审计。

    HARD：audit.log、reports/、config、cve_snapshot、agent_state.sqlite 不在白名单，
    本函数结构上无法触达它们（无对应路径收集分支）。
    """
    if scope not in ("session", "artifacts", "system", "all"):
        raise ValueError(f"未知清理范围: {scope}")
    removed = failed = 0
    scopes = ["session", "artifacts", "system"] if scope == "all" else [scope]
    for current in scopes:
        if current == "session":
            candidates = _session_paths()
        elif current == "artifacts":
            candidates = _artifact_paths()
        else:
            candidates = _system_paths(target)
            flush_local_dns_cache()
        for path in candidates:
            if _shred_delete(path):
                removed += 1
            else:
                failed += 1
    TempArtifactRegistry.clear()
    audit("trace_cleanup", {"scope": scope, "target": (target or "")[:128],
                            "removed": removed, "failed": failed})
    return {"removed": removed, "failed": failed}


def dry_run(scope: str = "session", target: str | None = None) -> list[str]:
    """列出将被清理的路径（不删除）；供 CLI 预览确认。"""
    if scope == "all":
        scopes = ["session", "artifacts", "system"]
    else:
        scopes = [scope]
    out: list[str] = []
    for current in scopes:
        if current == "session":
            out.extend(str(p) for p in _session_paths())
        elif current == "artifacts":
            out.extend(str(p) for p in _artifact_paths())
        else:
            out.extend(str(p) for p in _system_paths(target))
    return sorted(set(out))
