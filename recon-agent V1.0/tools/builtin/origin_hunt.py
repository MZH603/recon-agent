"""builtin L3 CDN 判定与源站线索 hunting：多 DoH 分歧 / 证书 SAN / 历史 DNS。

HARD：候选真实 IP/旁站一律只记录不扫描（范围外资产代码层硬拦截天然生效）；
每 DoH 解析器 1 次查询；证书 1 次握手；历史 DNS 仅在配置 SecurityTrails key 时 1 次查询。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

DOH_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("google", "https://dns.google/resolve?name={domain}&type=A"),
    ("alidns", "https://dns.alidns.com/resolve?name={domain}&type=A"),
    ("quad9", "https://dns.quad9.net:5053/dns-query?name={domain}&type=A"),
    ("dns.sb", "https://doh.dns.sb/dns-query?name={domain}&type=A"),
)


def extract_a_from_doh(payload: dict) -> set[str]:
    """纯函数：DoH JSON → A 记录集合。"""
    out: set[str] = set()
    for answer in payload.get("Answer") or []:
        if answer.get("type") == 1 and answer.get("data"):
            out.add(str(answer["data"]))
    return out


def cdn_verdict(sets: dict[str, set[str]]) -> tuple[bool, str]:
    """纯函数：多解析器 A 集合 → (是否 CDN 判定, 理由)。"""
    unions = set().union(*sets.values()) if sets else set()
    if not unions:
        return False, "无有效 A 记录"
    if len(unions) > 4:
        return True, f"多解析器共返回 {len(unions)} 个不同 A 记录（任播/CDN 特征）"
    divergent = len({frozenset(s) for s in sets.values()}) > 1
    if divergent:
        return True, "解析器之间存在 A 记录分歧（CDN/智能解析特征）"
    return False, f"各解析器一致（{len(unions)} 个 A 记录）"


class OriginHuntParams(BaseModel):
    """源站线索参数。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="授权主域名")


class OriginHuntTool(BaseTool):
    """L3 CDN 判定 + 源站线索收集（只记录，不扫描候选源站）。"""

    name = "origin_hunt"
    description = "多 DoH 解析分歧 → CDN 判定；证书 SAN 反查 + 历史 DNS → 源站候选（只记录不扫描，L3）"
    risk_level = "高"
    min_level = 3
    params_model = OriginHuntParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, OriginHuntParams)
        domain = params.target.lower().rstrip(".")
        notes: list[str] = []

        # 1) 多 DoH A 记录分歧（每解析器 1 次查询，打公共 DoH，不碰目标）
        sets: dict[str, set[str]] = {}
        async def one_doh(name: str, tpl: str) -> None:
            try:
                status, _, body = await run_sync(
                    http_get, tpl.format(domain=domain), self._settings.CONNECT_TIMEOUT,
                    False, 100_000)
                if status == 200:
                    sets[name] = extract_a_from_doh(json.loads(body))
            except (OSError, ValueError, json.JSONDecodeError):
                notes.append(f"DoH {name} 失败（不重试）")

        await asyncio.gather(*[one_doh(n, t) for n, t in DOH_ENDPOINTS])
        is_cdn, reason = cdn_verdict(sets)

        # 2) 证书 SAN 反查（1 次握手；域名只记录，范围外候选不扫描）
        san, san_note = await self._cert_san(domain)
        if san_note:
            notes.append(san_note)

        # 3) 历史 DNS（SecurityTrails key 配置时；dns_history 里的历史 IP = 源站候选）
        history_ips: list[str] = []
        if (self._settings.SECURITYTRAILS_API_KEY or "").strip():
            history_ips, hist_note = await self._history_ips(domain)
            if hist_note:
                notes.append(hist_note)
        else:
            notes.append("历史 DNS 未启用（缺 SECURITYTRAILS_API_KEY）")

        current_ips = set().union(*sets.values()) if sets else set()
        candidate_origins = sorted(set(history_ips) - current_ips)  # 只记录
        data = {
            "target": domain,
            "resolver_a": {k: sorted(v) for k, v in sets.items()},
            "cdn_detected": is_cdn, "cdn_reason": reason,
            "cert_san": san,
            "current_ips": sorted(current_ips),
            "candidate_origins_record_only": candidate_origins[:20],
            "notes": notes,
        }
        evidence = [
            f"CDN 判定: {'是' if is_cdn else '否'} — {reason}",
            f"证书 SAN: {len(san)} 条；源站候选（仅记录）: {len(candidate_origins)}",
            "HARD：候选源站/旁站一律不扫描，仅记录待人工确认",
        ]
        return ToolResult(
            name=self.name, success=True, data=data, evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.7 if is_cdn or candidate_origins else 0.5,
        )

    async def _cert_san(self, domain: str) -> tuple[list[str], str]:
        """1 次 TLS 握手读证书 SAN（自签/不匹配照常读取，源站线索）。"""

        def _sync() -> list[str]:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # 源站线索收集：证书不匹配也要读
            with socket.create_connection((domain, 443), timeout=self._settings.CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert(binary_form=False) or {}
            san = cert.get("subjectAltName") or ()
            return [v for kind, v in san if kind == "DNS"]

        try:
            return await asyncio.wait_for(asyncio.to_thread(_sync), timeout=self._settings.CONNECT_TIMEOUT * 2), ""
        except (OSError, ssl.SSLError, ValueError) as exc:
            return [], f"证书 SAN 获取失败: {type(exc).__name__}（不重试）"

    async def _history_ips(self, domain: str) -> tuple[list[str], str]:
        """SecurityTrails 历史 A 记录（1 次查询）。"""
        from tools.adapters.datasources import get_adapter
        adapter = get_adapter("securitytrails", self._settings,
                              self._settings.SECURITYTRAILS_API_KEY, "")
        from urllib.parse import quote
        # 直连 history 端点（adapter 默认查 subdomains；此处复用其鉴权头）
        url, headers, params = adapter._build_request(domain, 1, 100)
        url = url.replace("/subdomains", "/history/dns/a")
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=self._settings.CONNECT_TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, params=params) as resp:
                    if resp.status != 200:
                        return [], f"SecurityTrails 历史 HTTP {resp.status}"
                    raw = await resp.json()
            ips: list[str] = []
            for record in raw.get("records") or []:
                for ip in record.get("ips") or []:
                    if ip not in ips:
                        ips.append(ip)
            return ips, ""
        except (aiohttp.ClientError, ValueError, json.JSONDecodeError) as exc:
            return [], f"历史 DNS 查询失败: {type(exc).__name__}（不重试）"
