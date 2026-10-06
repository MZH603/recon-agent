"""环境自检（--doctor）：工具可用性 / 网络连通 / API Key / 审计链 / CVE 快照。"""
from __future__ import annotations

import os
import platform as stdlib_platform
import sys
import urllib.request

from platforms.tools import find_tool
from rich.table import Table
from utils.logger import audit_path, console, verify_audit_chain


def _http_ok(url: str, timeout: int = 6) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, f"HTTP {resp.status}"
    except Exception as exc:  # noqa: BLE001 —— 自检只报告，不中断
        return False, type(exc).__name__


def _check(name: str, ok: bool, detail: str, table: Table, mark_ok: str = "✅ 可用") -> None:
    """向体检表追加一行。"""
    level = "✅" if ok else "❌"
    table.add_row(name, level, detail)


def run_doctor() -> int:
    """执行全部自检并打印体检表；返回 0（信息性，不作为门禁）。"""
    table = Table(title="recon-agent V1.0 环境自检", show_lines=False)
    table.add_column("检查项", style="cyan")
    table.add_column("状态")
    table.add_column("说明")

    version_ok = sys.version_info >= (3, 10)
    _check("Python ≥3.10", version_ok, f"当前 {stdlib_platform.python_version()}", table)

    for tool, impact in (("nmap", "缺失 → builtin_socket 降级"),
                         ("httpx", "缺失 → builtin 指纹降级"),
                         ("bandit", "缺失 → 沙箱拒绝执行脚本（pip install bandit）"),
                         ("docker", "缺失 → 沙箱宿主机降级隔离")):
        found = find_tool(tool)
        detail = found if found else impact
        _check(f"外部工具 {tool}", bool(found), detail, table)

    for name, url in (("DoH 解析 (alidns)", "https://dns.alidns.com/resolve?name=example.com&type=1"),
                      ("DoH 解析 (google)", "https://dns.google/resolve?name=example.com&type=1"),
                      ("CT 源 (certspotter)", "https://api.certspotter.com/v1/issuances?domain=example.com"),
                      ("CT 源 (crt.sh)", "https://crt.sh/?q=example.com"),
                      ("Wayback CDX", "https://web.archive.org/cdx/search/cdx?url=example.com&limit=10")):
        ok, detail = _http_ok(url)
        _check(f"网络 {name}", ok, detail + ("" if ok else "（对应功能降级）"), table)

    keys = {k: os.environ.get(k) for k in
            ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY")}
    configured = [k for k, v in keys.items() if v]
    _check("模型 API Key", bool(configured),
           f"已配置: {', '.join(configured)}" if configured else "未配置 → 仅离线流水线/--mcp 可用", table)

    ok_chain, count, msg = verify_audit_chain()
    _check("审计日志哈希链", ok_chain, f"{audit_path()} · {count} 条 · {msg}", table)

    from platforms.paths import get_cve_dir

    snapshot = get_cve_dir() / "snapshot.json"
    _check("CVE 快照", snapshot.exists(),
           str(snapshot) if snapshot.exists() else "缺失 → python -m knowledge.snapshot 构建", table)

    console().print(table)
    console().print("[yellow]提示：内网/环回目标需 --lab（仅限自有实验环境）；.gov/.mil 绝对拒绝。[/yellow]")
    return 0
