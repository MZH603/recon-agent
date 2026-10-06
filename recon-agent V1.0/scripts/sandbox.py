"""LLM 生成脚本的三层沙箱（HARD：AST + Bandit + 运行时隔离，任一层失败即拒绝执行）。"""
from __future__ import annotations

import ast
import json
import sys
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

from platforms.subprocess import run_command
from platforms.tools import find_tool
from utils.config import Settings, get_settings
from utils.logger import audit, warn

# HARD: 黑名单双保险之一——AST 层
FORBIDDEN_MODULES = {"os", "sys", "shutil", "subprocess", "importlib", "ctypes", "requests"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "globals", "locals", "vars", "open"}
FORBIDDEN_ATTR_CALLS = {"write_text", "write_bytes", "unlink", "rmdir", "mkdir", "rename", "replace", "chmod"}
WRITE_MODE_CHARS = {"w", "a", "x", "+"}


class SandboxResult(BaseModel):
    """沙箱静态校验结果。"""

    allowed: bool
    reason: str = ""
    bandit_findings: list[str] = Field(default_factory=list)


def validate_script(code: str) -> SandboxResult:
    """第一层：AST 静态校验（黑名单导入/危险调用/文件写/网络外传）。

    注意：AST 可被字符串拼接混淆（如 "os"+"."+"system"），因此必须叠加
    Bandit 扫描 + HITL 确认 + 运行时隔离，三层缺一不可（HARD）。
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return SandboxResult(allowed=False, reason=f"语法错误: {exc}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    return SandboxResult(allowed=False, reason=f"禁止导入模块: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in FORBIDDEN_MODULES:
                return SandboxResult(allowed=False, reason=f"禁止导入模块: {node.module}")
        elif isinstance(node, ast.Call):
            reason = _check_call(node)
            if reason:
                return SandboxResult(allowed=False, reason=reason)
    return SandboxResult(allowed=True)


def _check_call(node: ast.Call) -> str | None:
    """单条 Call 节点黑名单检查。"""
    if isinstance(node.func, ast.Name):
        if node.func.id in FORBIDDEN_CALLS:
            return f"禁止调用 {node.func.id}()"
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in FORBIDDEN_ATTR_CALLS:
            return f"禁止调用 {node.func.attr}()（文件写/删除）"
        if node.func.attr in {"Request", "urlopen"}:
            for kw in node.keywords:  # HARD: 禁止网络外传（POST/data）
                if kw.arg in {"data", "method"}:
                    return "禁止网络外传（POST/data）"
    return None


async def run_bandit(code: str, work_dir: Path) -> list[str]:
    """第二层：Bandit 扫描，返回高危发现；bandit 缺失视为沙箱不完整（HARD：拒绝执行）。"""
    bandit = find_tool("bandit")
    if not bandit:
        return ["[bandit-missing] bandit 未安装，沙箱三层缺一，拒绝执行（pip install bandit）"]
    work_dir.mkdir(parents=True, exist_ok=True)
    script = work_dir / "candidate_script.py"
    script.write_text(code, encoding="utf-8", newline="")
    ret, out, err = await run_command([bandit, "-q", "-f", "json", str(script)], timeout=60)
    if ret not in (0, 1):  # bandit 约定：0=无发现 1=有发现
        return [f"[bandit-error] {err[:200]}"]
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return ["[bandit-error] 输出解析失败"]
    return [
        f"{r.get('test_id')}: {r.get('issue_text')}"
        for r in data.get("results", [])
        if r.get("issue_severity") == "HIGH"
    ]


async def execute(code: str, confirmed: bool, settings: Settings | None = None) -> tuple[int, str, str]:
    """第三层：运行时隔离执行，返回 (exit_code, stdout, stderr)。

    - confirmed=False 直接拒绝（HITL 门，HARD）；
    - Docker 可用且配置开启 → 容器隔离（断网/只读/降权/内存限制）；
    - 否则降级为宿主机直跑（超时强杀 + 审计，隔离性减弱必须告知）。
    """
    settings = settings or get_settings()
    if not settings.SANDBOX_ENABLED:
        return 126, "", "[sandbox] 沙箱已禁用，拒绝执行（HARD）"
    if not confirmed:
        audit("script_blocked", {"reason": "未经用户确认"})
        return 125, "", "[sandbox] 未经用户确认，拒绝执行（HARD）"
    check = validate_script(code)
    if not check.allowed:
        audit("script_blocked", {"reason": check.reason})
        return 126, "", f"[sandbox] AST 校验失败: {check.reason}"
    findings = await run_bandit(code, Path(tempfile.gettempdir()) / "recon-agent-sandbox")
    if findings:
        audit("script_blocked", {"reason": findings})
        return 126, "", f"[sandbox] Bandit 拦截: {findings}"

    docker = find_tool("docker")
    if settings.SANDBOX_USE_DOCKER and docker:
        args = [docker, "run", "--rm", "-i", f"--network={settings.SANDBOX_NETWORK}",
                "--read-only", "--user=1000", "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                f"--memory={settings.SANDBOX_MEMORY_LIMIT}", "python:3.11-slim"]
        ret, out, err = await run_command(args, timeout=settings.SANDBOX_TIMEOUT, input_data=code)
        audit("script_exec_docker", {"exit": ret})
        return ret, out, err

    work = Path(tempfile.gettempdir()) / "recon-agent-sandbox"
    work.mkdir(parents=True, exist_ok=True)
    script = work / "candidate_script.py"
    script.write_text(code, encoding="utf-8", newline="")
    ret, out, err = await run_command(
        [sys.executable, "-I", str(script)], timeout=settings.SANDBOX_TIMEOUT
    )
    audit("script_exec_local", {"exit": ret})
    warn("[sandbox] 当前为宿主机降级隔离（AST+Bandit+HITL 兜底，建议 Linux+Docker）")
    return ret, out, err
