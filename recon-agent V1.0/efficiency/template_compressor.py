"""模板化压缩（HARD：对高频冗长输出只注入"变量部分"，省去重复文本）。"""
from __future__ import annotations

import re

_NMAP_PORT = re.compile(r"^\s*(\d+)/tcp\s+(open|closed|filtered)\s+(\S+)", re.M)
_HTTPX_LINE = re.compile(r"^(https?://\S+)\s+\[(\d{3})\]\s*(?:\[(.*?)\])?\s*(.*)$")


def compress(tool_name: str, stdout: str) -> dict | None:
    """按工具选择模板；无模板命中返回 None（调用方回退原文截断）。"""
    if tool_name == "nmap_scan":
        return _compress_nmap(stdout)
    if tool_name == "httpx_probe":
        return _compress_httpx(stdout)
    return None


def _compress_nmap(stdout: str) -> dict | None:
    """nmap 输出 → {ports: [{port, state, service}]}（去掉表头横幅）。"""
    rows = [{"port": int(p), "state": s, "service": svc} for p, s, svc in _NMAP_PORT.findall(stdout)]
    return {"template": "nmap_ports", "ports": rows} if rows else None


def _compress_httpx(stdout: str) -> dict | None:
    """httpx 行输出 → {url, status, tech, title}。"""
    match = _HTTPX_LINE.match(stdout.strip().splitlines()[0]) if stdout.strip() else None
    if not match:
        return None
    url, status, tech, title = match.groups()
    return {"template": "httpx_line", "url": url, "status": int(status),
            "tech": tech or "", "title": (title or "").strip()[:80]}
