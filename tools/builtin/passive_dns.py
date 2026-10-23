"""无 Key 被动子域数据源 + 有界 DNS 字典验证。

HARD：仅访问第三方情报服务与公共解析器，不触碰目标业务端口；
字典 ≤600 条；DNS 验证并发 ≤10。
"""
from __future__ import annotations

import asyncio
from platforms.sync_worker import run_sync
import json
import re
import socket
import urllib.request
from pathlib import Path

from tools.builtin.webfetch import http_get, http_get_text
from security.stealth import StealthRateLimiter
from utils.config import Settings

WORDLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "subnames.txt"
WORDLIST_CAP = 600          # HARD: 字典上限
BRUTE_CONCURRENCY = 10      # HARD: DNS 验证并发（仅解析器，非目标）
BRUTE_TIMEOUT = 4


def load_wordlist() -> tuple[str, ...]:
    """加载内置字典（去重、小写、截断到上限）。"""
    try:
        words = WORDLIST_PATH.read_text(encoding="utf-8").split()
    except OSError:
        return ()
    words = [w.strip().lower() for w in words if w.strip() and re.match(r"^[\w\-]+$", w)]
    return tuple(dict.fromkeys(words))[:WORDLIST_CAP]


def _in_scope(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


async def _aget(url: str, settings: Settings, timeout_mult: int = 1) -> str:
    _, _, body = await run_sync(http_get, url, settings.CONNECT_TIMEOUT * timeout_mult, max_bytes=2_000_000)
    return body


async def otx_subdomains(domain: str, settings: Settings) -> set[str]:
    """AlienVault OTX 被动 DNS（无 Key）。"""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = json.loads(await _aget(url, settings))
    names = {str(p.get("hostname", "")).lower().rstrip(".") for p in data.get("passive_dns", [])}
    return {n for n in names if n and _in_scope(n, domain)}


async def rapiddns_subdomains(domain: str, settings: Settings) -> set[str]:
    """RapidDNS HTML 表（无 Key）。"""
    html = await _aget(f"https://rapiddns.io/subdomains/{domain}?full=1", settings)
    pattern = r">([\w\-]+(?:\.[\w\-]+)*\." + re.escape(domain) + r")<"
    return {h.lower().rstrip(".") for h in re.findall(pattern, html)}


async def hackertarget_hosts(domain: str, settings: Settings) -> set[str]:
    """HackerTarget hostsearch API（无 Key，限频）。"""
    text = await _aget(f"https://api.hackertarget.com/hostsearch/?q={domain}", settings)
    hosts: set[str] = set()
    for line in text.splitlines():
        host = line.split(",")[0].strip().lower().rstrip(".")
        if host and _in_scope(host, domain):
            hosts.add(host)
    return hosts


async def urlscan_subdomains(domain: str, settings: Settings) -> set[str]:
    """urlscan.io 搜索 API（无 Key，限频）。"""
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    data = json.loads(await _aget(url, settings))
    names: set[str] = set()
    for result in data.get("results", []):
        for key in ("page", "task"):
            value = (result.get(key) or {}).get("domain", "")
            if value:
                names.add(str(value).lower().rstrip("."))
    return {n for n in names if n and _in_scope(n, domain)}


async def dns_brute(domain: str, limit: int) -> set[str]:
    """有界字典 DNS 验证：仅查系统解析器，并发 10（HARD），失败不重试。"""
    semaphore = asyncio.Semaphore(BRUTE_CONCURRENCY)

    async def check(prefix: str) -> str | None:
        host = f"{prefix}.{domain}"
        async with semaphore:
            try:
                await asyncio.wait_for(
                    run_sync(socket.getaddrinfo, host, None), timeout=BRUTE_TIMEOUT
                )
                return host
            except (OSError, asyncio.TimeoutError):
                return None  # NXDOMAIN/超时 → 跳过

    words = load_wordlist()[:limit]
    results = await asyncio.gather(*(check(word) for word in words))
    return {r for r in results if r}
