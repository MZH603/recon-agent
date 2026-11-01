"""DNS 反溯源（HARD：默认关闭；关闭时系统解析，行为不变）。

启用后域名解析改走 DoH（HTTPS JSON API），且 DoH 请求自身经匿名出口发送 ——
本地解析器不再产生针对目标的明文 DNS 查询（防 ISP/本地 resolver 关联侦察意图）。
doh_strict=True 时 DoH 失败拒绝出站而非降级系统解析（彻底不产生本地 DNS 查询）。
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
import urllib.error
import urllib.request

from security.anonymity.config import DOH_CACHE_TTL_SECONDS, DOH_TIMEOUT_SECONDS
from security.anonymity.egress import build_opener
from utils.logger import audit

_RTYPE_A = 1
_RTYPE_AAAA = 28
_STATUS_NOERROR = 0
_JSON_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

_cache: dict[str, tuple[float, list[str]]] = {}
_cache_lock = threading.Lock()
_last_good: str = ""


class DohUnavailableError(Exception):
    """DoH 全部解析器失败（doh_strict=True 时调用方须拒绝出站）。"""


def _is_numeric(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def doh_resolve(host: str, rtype: str = "A", timeout: float = DOH_TIMEOUT_SECONDS) -> list[str]:
    """DoH 解析（RFC 8484 JSON API）；全部解析器失败抛 DohUnavailableError。"""
    global _last_good
    if _is_numeric(host):
        return [host]
    cache_key = f"{host}|{rtype}"
    now = time.time()
    with _cache_lock:
        hit = _cache.get(cache_key)
        if hit and hit[0] > now:
            return list(hit[1])
    rcode_num = _RTYPE_AAAA if rtype.upper() == "AAAA" else _RTYPE_A
    import tools.builtin.dns_query as _dq  # 复用解析器清单与码表（HARD：不重复定义）
    resolvers = _dq.DOH_RESOLVERS
    last_exc: Exception | None = None
    order = sorted(resolvers, key=lambda r: r[0] != _last_good)
    for name, base in order:
        try:
            url = f"{base}?name={host}&type={rcode_num}"
            opener = build_opener()  # 匿名关闭=直连（DoH 解析器非目标）；开启=经出口
            req = urllib.request.Request(url, headers={"User-Agent": _JSON_USER_AGENT,
                                                       "Accept": "application/dns-json"})
            with opener.open(req, timeout=timeout) as resp:
                payload = json.loads(resp.read(64_000).decode("utf-8", "replace"))
            if payload.get("Status") != _STATUS_NOERROR:
                raise DohUnavailableError(f"DoH 返回 Status={payload.get('Status')}: {name}")
            answers = [a["data"] for a in payload.get("Answer", [])
                       if a.get("type") == rcode_num]
            _last_good = name
            with _cache_lock:
                _cache[cache_key] = (now + DOH_CACHE_TTL_SECONDS, answers)
            if not answers:
                raise DohUnavailableError(f"DoH 无 {rtype} 记录: {host}（{name}）")
            audit("doh_resolved", {"host": host[:128], "resolver": name, "count": len(answers)})
            return answers
        except (OSError, ValueError, KeyError, DohUnavailableError) as exc:
            last_exc = exc
            continue
    raise DohUnavailableError(f"DoH 全部解析器失败: {host}（{last_exc}）")


def clear_doh_cache() -> None:
    with _cache_lock:
        _cache.clear()


def resolve_host(host: str, port: int, config=None) -> list[tuple]:
    """统一解析入口：返回 getaddrinfo 兼容结构（AF_INET/AF_INET6, SOCK_STREAM, ..., (ip, port)）。

    - 未启用 DoH → socket.getaddrinfo（历史行为，由调用方决定同步/子进程）；
    - 启用 → DoH 优先；doh_strict=False 失败降级系统解析（审计），
             doh_strict=True 失败抛 DohUnavailableError（调用方拒绝出站）。
    """
    cfg = config
    if cfg is None:
        from utils.config import get_settings
        cfg = get_settings().anonymity
    if _is_numeric(host):
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                  flags=socket.AI_NUMERICHOST)
    if not cfg.doh_enabled:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    try:
        addrs = doh_resolve(host, "A")
        try:
            addrs += doh_resolve(host, "AAAA")
        except DohUnavailableError:
            pass  # AAAA 缺失不致命（多数目标仅有 A）
        results: list[tuple] = []
        for ip in addrs:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            results.append((family, socket.SOCK_STREAM, 0, "", (ip, port)))
        if results:
            return results
        raise DohUnavailableError(f"DoH 返回空地址: {host}")
    except DohUnavailableError:
        if cfg.doh_strict:
            audit("doh_strict_blocked", {"host": host[:128]})
            raise
        audit("doh_fallback_system", {"host": host[:128],
                                      "risk": "local-dns-query-leak"})
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
