"""子域名枚举与递归拓线（L0 纯被动，多源）。

数据源（对照 OneForAll 的无 Key 模块校准）：
- CT 证书透明度链（crt.sh → certspotter，递归一层）
- AlienVault OTX / RapidDNS / HackerTarget / urlscan（无 Key 被动 DNS）
- TLS 证书 SAN（单次握手）
- 有界常见前缀 DNS 字典验证（≤600，仅查公共解析器）

递归语义（HARD 有界）：对发现的每个子域（≤10 个）再查一层 CT；全链路不触碰目标业务端口。
"""
from __future__ import annotations

import asyncio
from platforms.sync_worker import run_sync
import hashlib
import json
import socket
import ssl

from pydantic import BaseModel, Field

from collectors.asset_expander import _crtsh_subdomains
from security.stealth import StealthRateLimiter, normalize_host
from tools.base import BaseTool, ToolResult
from tools.builtin.passive_dns import (
    WORDLIST_CAP,
    dns_brute,
    hackertarget_hosts,
    load_wordlist,
    otx_subdomains,
    rapiddns_subdomains,
    urlscan_subdomains,
)
from utils.config import Settings, get_settings

MAX_HOSTS_CAP = 100      # HARD: 结果上限
RECURSION_LIMIT = 10     # HARD: 递归子域数上限（一层）


def certificate_names(domain, timeout):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            return [name for _, name in tls.getpeercert().get('subjectAltName', [])]


class SubdomainParams(BaseModel):
    """子域枚举参数（有界）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$")
    recursive: bool = Field(True, description="对发现的子域再查询一层 CT（≤10 个）")
    brute: bool = Field(True, description="内置字典 DNS 验证（≤600 条，仅查解析器）")
    prefix_limit: int = Field(600, ge=50, le=WORDLIST_CAP)
    max_hosts: int = Field(50, ge=1, le=MAX_HOSTS_CAP)


def filter_scope(hosts: set[str], domain: str) -> list[str]:
    """范围过滤（纯函数，便于测试）：仅保留主域及其子域；通配符名不作为主机处理。"""
    out = {
        h for h in hosts
        if (h == domain or h.endswith("." + domain)) and "*" not in h
    }
    return sorted(out)


class SubdomainEnumTool(BaseTool):
    """子域名枚举（L0）：CT 链 + OTX/RapidDNS/HackerTarget/urlscan + SAN + 字典验证 + 递归。"""

    name = "subdomain_enum"
    description = "子域名枚举与递归拓线：8 类数据源（CT/OTX/RapidDNS/HackerTarget/urlscan/SAN/字典/递归）+ 存活解析"
    risk_level = "低"
    min_level = 0
    params_model = SubdomainParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.L0_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """多源枚举 → 递归一层 → 范围过滤 → 存活解析。"""
        assert isinstance(params, SubdomainParams)
        domain = normalize_host(params.target)
        sources: dict[str, int] = {}
        hosts: set[str] = {domain}
        notes: list[str] = []

        # 并发采集被动 DNS 源（HARD: 仅访问第三方 API，不影响目标）
        passive_names = ("otx", "rapiddns", "hackertarget", "urlscan")
        passive_tasks = [
            self._safe(f)(domain) for f in
            (otx_subdomains, rapiddns_subdomains, hackertarget_hosts, urlscan_subdomains)
        ]
        passive_results = await asyncio.gather(*passive_tasks)
        for name, (found, error) in zip(passive_names, passive_results):
            hosts.update(found)
            sources[name] = len(found)
            if error:
                notes.append(f"{name} 不可达（不重试）: {error[:80]}")

        # CT 根查询（顺序：递归依赖）
        ct_found, ct_error = await self._ct_root(domain)
        hosts.update(ct_found)
        sources["ct_root"] = len(ct_found)

        recursion_found = 0
        if params.recursive:
            base = await _crtsh_subdomains(domain, self._settings)
            for sub in base["in_scope"][:RECURSION_LIMIT]:
                sub_result = await _crtsh_subdomains(sub, self._settings)
                hosts.update(sub_result["in_scope"])
                recursion_found += len(sub_result["in_scope"])
            sources["ct_recursive"] = recursion_found

        if params.brute:
            hits = await dns_brute(domain, params.prefix_limit)
            hosts.update(hits)
            sources["dns_brute"] = len(hits)

        san = await self._cert_san(domain)
        hosts.update(san)
        sources["tls_san"] = len(san)

        in_scope = filter_scope(hosts, domain)[: params.max_hosts]
        alive = await self._resolve_alive(in_scope)
        payload = {
            "domain": domain, "subdomains": in_scope, "sources": sources,
            "san": san, "alive": alive, "recursive": params.recursive,
            "wordlist_size": len(load_wordlist()), "notes": notes,
        }
        return ToolResult(
            name=self.name,
            success=True,
            data=payload,
            evidence=[
                f"多源命中: {sources}",
                f"递归一层: +{recursion_found} 条（≤{RECURSION_LIMIT} 子域）",
                f"TLS SAN: {len(san)} 条（单次握手）",
                f"存活解析: {len(alive)}/{len(in_scope)}",
            ],
            source_hash=hashlib.sha256(
                json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()[:64],
            confidence=0.8,
        )

    def _safe(self, collector):
        """单源失败收敛为 (空集, 错误信息)，不拖垮整体（显式失败不重试）。"""

        async def wrapper(domain: str) -> tuple[set[str], str]:
            try:
                return await collector(domain, self._settings), ""
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return set(), f"{type(exc).__name__}: {exc}"
        return wrapper

    async def _ct_root(self, domain: str) -> tuple[set[str], str]:
        base = await _crtsh_subdomains(domain, self._settings)
        return set(base["in_scope"]), ""

    async def _cert_san(self, domain: str) -> list[str]:
        """单次 TLS 握手读取证书 SAN（443，只读）。"""
        try:
            async with self._limiter.slot():
                raw = await run_sync(certificate_names, domain, self._settings.CONNECT_TIMEOUT)
            return [n.lower().rstrip(".") for n in raw]
        except (OSError, ssl.SSLError, ValueError):
            return []  # 无证书/握手失败 → 如实返回空（不重试）

    async def _resolve_alive(self, hosts: list[str]) -> list[dict]:
        """存活解析（精准扫描前置过滤）：逐主机系统解析。"""
        alive: list[dict] = []
        for host in hosts:
            async with self._limiter.slot():
                try:
                    infos = await asyncio.wait_for(
                        run_sync(socket.getaddrinfo, host, None), timeout=5
                    )
                    ips = sorted({i[4][0] for i in infos})
                    alive.append({"host": host, "ips": ips[:3]})
                except (OSError, asyncio.TimeoutError):
                    continue
        return alive
