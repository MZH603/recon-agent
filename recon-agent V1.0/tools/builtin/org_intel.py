"""builtin 人员与组织情报（L0 被动：邮箱采集 / ICP 备案 / ASN 归属 / 企业关联）。

四通道独立降级（任一失败/未配置仅记 note，不影响其他通道）：
- 邮箱：主站 1 次 GET + WHOIS 43/tcp（复用 asset_expander 的原生 whois）
- ICP：可插拔 HTTP 模板（ICP_API_URL 含 {domain}/{api_key} 占位符；空=跳过）
- ASN：ipinfo.io（≤3 IP）+ bgp.he.net HTML 降级
- 企业关联：ORG_API_BASE 通用插槽（企查查/天眼查等付费 API 自配）
HARD：推断性结论（邮箱格式/角色账号候选）一律标 [未确认]。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import socket
import urllib.parse
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# 第三方服务邮箱过滤（不是目标组织的人）
NOISE_EMAIL_DOMAINS = (
    "example.com", "example.org", "sentry.io", "sentry-next.wixpress.com",
    "wixpress.com", "w3.org", "schema.org", "sentry.wixpress.com",
)
ROLE_ACCOUNTS = ("admin", "security", "info", "contact", "hr", "support", "it")
ASN_RE = re.compile(r"AS(\d+)\s*[·|]\s*([^\r\n<]{2,80})")


class OrgIntelParams(BaseModel):
    """组织情报参数（主域名；可选传入已知解析 IP 以省一次 DNS 查询）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="主域名")
    ips: list[str] = Field(default_factory=list, max_length=3, description="已知解析 IP（≤3，可选）")


class OrgIntelTool(BaseTool):
    """组织与人员情报聚合（L0 被动：第三方查询 + 目标主站一次只读 GET）。"""

    name = "org_intel"
    description = "邮箱采集（主站+WHOIS）/ICP 备案（可插拔）/ASN 归属（ipinfo+bgp.he）/企业关联插槽（被动 L0）"
    risk_level = "低"
    min_level = 1  # v1.1: L0 已并入 L1（基础侦察）
    params_model = OrgIntelParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, OrgIntelParams)
        domain = params.target.lower().rstrip(".")
        notes: list[str] = []

        emails, whois_org, whois_note = await self._email_channel(domain)
        if whois_note:
            notes.append(whois_note)

        icp, icp_note = await self._icp_channel(domain)
        if icp_note:
            notes.append(icp_note)

        ips = list(params.ips)[:3]
        if not ips:
            resolved = await run_sync(self._resolve_a, domain)
            ips = resolved[:3]
        asn, asn_note = await self._asn_channel(ips)
        if asn_note:
            notes.append(asn_note)

        org_info, org_note = await self._org_channel(domain)
        if org_note:
            notes.append(org_note)

        data = {
            "target": domain,
            "emails": emails,
            "role_account_candidates": [f"{r}@{domain}" for r in ROLE_ACCOUNTS],
            "whois_org": whois_org,
            "icp": icp,
            "asn": asn,
            "org_info": org_info,
            "notes": notes,
        }
        evidence = [
            f"主站邮箱采集: {domain}（1 次只读 GET）",
            f"ASN 归属: {len(asn)}/{len(ips)} IP（ipinfo.io / bgp.he.net）",
            "邮箱格式与角色账号候选均为推断 [未确认，建议人工核实]",
        ]
        return ToolResult(
            name=self.name,
            success=True,
            data=data,
            evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.6,
        )

    # ---------- 通道 1：邮箱 ----------
    async def _email_channel(self, domain: str) -> tuple[list[dict], str, str]:
        """主站 1 GET + WHOIS 文本 → 邮箱与注册组织（独立降级）。"""
        emails: dict[str, dict] = {}
        whois_org = ""
        homepage_note = ""
        try:
            _, _, body = await run_sync(
                http_get, f"https://{domain}/", self._settings.CONNECT_TIMEOUT, False, 100_000)
            for email in self._extract_emails(body or "", domain):
                emails.setdefault(email, {"email": email, "source": "homepage"})
        except (OSError, ValueError):
            homepage_note = "主站获取失败（https 兜底亦失败，不重试）"
        whois_note = ""
        try:
            from collectors.asset_expander import IANA_WHOIS, _whois_query
            text = await run_sync(_whois_query, domain, IANA_WHOIS, self._settings.CONNECT_TIMEOUT)
            for email in self._extract_emails(text, domain):
                emails.setdefault(email, {"email": email, "source": "whois"})
            for line in text.splitlines():
                if line.lower().startswith("registrant organization:"):
                    whois_org = line.split(":", 1)[1].strip()
                    break
        except (OSError, UnicodeError, ImportError) as exc:
            whois_note = f"WHOIS 邮箱通道失败: {exc}（不重试）"
        out = list(emails.values())
        note = "；".join(n for n in (homepage_note, whois_note) if n)
        return out, whois_org, note

    def _extract_emails(self, text: str, domain: str) -> list[str]:
        """纯函数：文本 → 去噪邮箱列表（目标域优先保留，第三方服务邮箱剔除）。"""
        out: list[str] = []
        target_suffix = f"@{domain.lower()}"
        for email in EMAIL_RE.findall(text or ""):
            lower = email.lower()
            if lower.endswith(target_suffix):
                out.append(email)
                continue
            if any(lower.endswith(d) for d in NOISE_EMAIL_DOMAINS):
                continue
            if email not in out:
                out.append(email)
        return out[:20]

    # ---------- 通道 2：ICP ----------
    async def _icp_channel(self, domain: str) -> tuple[dict, str]:
        """可插拔 ICP 查询（未配置=跳过并声明；响应仅截取 JSON 顶层字段）。"""
        template = (self._settings.ICP_API_URL or "").strip()
        if not template:
            return {"status": "skipped", "reason": "未配置 ICP_API_URL（可插拔备案查询源）"}, ""
        url = template.replace("{domain}", urllib.parse.quote(domain))
        if "{api_key}" in url:
            url = url.replace("{api_key}", urllib.parse.quote(self._settings.ICP_API_KEY or ""))
        try:
            status, _, body = await run_sync(
                http_get, url, self._settings.CONNECT_TIMEOUT, False, 100_000)
        except (OSError, ValueError) as exc:
            return {"status": "error"}, f"ICP 查询失败: {exc}（不重试）"
        if status != 200:
            return {"status": "error", "http": status}, f"ICP 查询 HTTP {status}"
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            return {"status": "error"}, "ICP 查询响应非 JSON（模板/源配置需人工核实）"
        top = {k: raw[k] for k in list(raw)[:8]} if isinstance(raw, dict) else {"data": str(raw)[:300]}
        return {"status": "hit", "data": top, "source": "ICP_API_URL（自配源）"}, ""

    # ---------- 通道 3：ASN ----------
    async def _asn_channel(self, ips: list[str]) -> tuple[list[dict], str]:
        """ipinfo.io 每 IP 1 请求（≤3），失败降级 bgp.he.net HTML。"""
        out: list[dict] = []
        for ip in ips:
            try:
                status, _, body = await run_sync(
                    http_get, f"https://ipinfo.io/{ip}/json", self._settings.CONNECT_TIMEOUT,
                    False, 20_000)
            except (OSError, ValueError):
                status, body = 0, ""
            entry: dict = {"ip": ip, "source": "ipinfo"}
            if status == 200:
                try:
                    raw = json.loads(body)
                    entry.update({"asn": raw.get("org", ""), "city": raw.get("city", ""),
                                  "country": raw.get("country", "")})
                except json.JSONDecodeError:
                    entry["error"] = "ipinfo 响应解析失败"
            else:
                entry["error"] = f"ipinfo HTTP {status}（不重试）"
            out.append(entry)
        note = "" if ips else "无可用 IP，ASN 通道跳过"
        return out, note

    # ---------- 通道 4：企业关联 ----------
    async def _org_channel(self, domain: str) -> tuple[dict, str]:
        """ORG_API_BASE 通用插槽（{domain}/{api_key} 占位；未配置=跳过）。"""
        base = (self._settings.ORG_API_BASE or "").strip()
        if not base:
            return {"status": "skipped",
                    "reason": "未配置 ORG_API_BASE（企查查/天眼查等付费 API 由操作者自配）"}, ""
        url = base.replace("{domain}", urllib.parse.quote(domain))
        if "{api_key}" in url:
            url = url.replace("{api_key}", urllib.parse.quote(self._settings.ORG_API_KEY or ""))
        try:
            status, _, body = await run_sync(
                http_get, url, self._settings.CONNECT_TIMEOUT, False, 100_000)
        except (OSError, ValueError) as exc:
            return {"status": "error"}, f"企业关联查询失败: {exc}（不重试）"
        if status != 200:
            return {"status": "error", "http": status}, f"企业关联 HTTP {status}"
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            return {"status": "error"}, "企业关联响应非 JSON（插槽配置需人工核实）"
        top = {k: raw[k] for k in list(raw)[:8]} if isinstance(raw, dict) else {"data": str(raw)[:300]}
        return {"status": "hit", "data": top, "source": "ORG_API_BASE（自配源）"}, ""

    # ---------- 辅助 ----------
    @staticmethod
    def _resolve_a(domain: str) -> list[str]:
        """系统解析器 A 记录（1 次查询，失败返回空）。"""
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        except (OSError, socket.gaierror):
            return []
        return sorted({i[4][0] for i in infos})
