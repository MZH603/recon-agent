"""builtin Web 指纹（L0 被动：单次只读 GET；Header/meta/路径三源识别 + 版本精确提取）。

支持 target 带端口（如 127.0.0.1:8080），用于非标准端口与本地靶场。
"""
from __future__ import annotations

import asyncio
from platforms.sync_worker import run_sync
import hashlib
import ipaddress
import re
import urllib.parse

from pydantic import BaseModel, Field

from security.stealth import StealthRateLimiter, normalize_host, random_user_agent
from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from tools.builtin.signatures import (
    BODY_SIGNATURES,
    HEADER_SIGNATURES,
    SCRIPT_LIB_NAMES,
    SCRIPT_VERSION_RE,
    SECURITY_HEADER_SIGNATURES,
    VERSION_HEADER_SIGNATURES,
)
from utils.config import Settings, get_settings


class FingerprintParams(BaseModel):
    """指纹探测参数：单次只读 GET（支持 host 或 host:port 或完整 URL）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="主机/主机:端口/URL")
    scope: str = Field("tech", pattern=r"^(tech|main|subdomain)$")


def split_target(target: str) -> tuple[str, int | None, str]:
    """解析目标为 (主机, 端口|None, scheme)（纯函数，便于测试）。

    支持：域名 / host:port / IPv6 裸地址 / [IPv6]:port / 完整 URL。
    """
    raw = target.strip()
    if raw.lower().startswith(("http://", "https://")):
        parts = urllib.parse.urlsplit(raw)
        return parts.hostname or raw, parts.port, parts.scheme
    if raw.startswith("[") and "]" in raw:      # [IPv6]:port 括号形式
        host, _, rest = raw[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:]), ""
        return host, None, ""
    if raw.count(":") == 1:                     # 单冒号 → host:port（IPv6 多冒号不会误入）
        host, _, port = raw.rpartition(":")
        if host and port.isdigit():
            return host, int(port), ""
    return raw, None, ""                        # 域名 / 裸 IPv6 整体返回


class FingerprintTool(BaseTool):
    """技术栈识别（Header + meta generator + 页面特征 + robots/sitemap 线索 + 版本）。"""

    name = "fingerprint"
    description = "单次 GET 识别 Web 技术栈：Server/中间件/语言/框架/CMS/版本/WAF/CDN（被动 L0，带来源）"
    risk_level = "低"
    min_level = 0
    params_model = FingerprintParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.L0_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """主页面 GET + robots/sitemap 两个补充 GET（共 ≤3 次只读请求）。"""
        assert isinstance(params, FingerprintParams)
        host, port, scheme_hint = split_target(params.target)
        netloc = f"{host}:{port}" if port else host
        first_scheme = "http" if scheme_hint == "http" else "https"
        is_ip = _is_ip(host)
        async with self._limiter.slot():
            status, headers, body = await run_sync(
                self._fetch, f"{first_scheme}://{netloc}/", insecure=is_ip)
        used_scheme = first_scheme
        if status == 0 and first_scheme == "https":  # https 失败不重试（HARD），http 兜底一次
            used_scheme = "http"
            async with self._limiter.slot():
                status, headers, body = await run_sync(self._fetch, f"http://{netloc}/")
        if status == 0:
            return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")
        insecure_note = "，[证书校验跳过: IP 目标]" if is_ip and used_scheme == "https" else ""
        findings: dict = {}
        _apply_headers(headers, findings)
        _apply_body(body, findings)
        robots, sitemap = await self._fetch_aux(netloc, used_scheme)
        card_confidence = max([f["confidence"] for f in findings.values()], default=0.5)
        card = {
            "host": netloc, "status": status, "title": _title(body),
            "scheme": used_scheme, "confidence": card_confidence,
            "tech": findings, "robots_hints": robots, "sitemap_hints": sitemap,
        }
        return ToolResult(
            name=self.name,
            success=True,
            data=card,
        evidence=[f"HTTP {status} Header: {netloc}{insecure_note}",
                  f"页面特征: {netloc}"],
            source_hash=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=card_confidence,
        )

    def _fetch(self, url: str, insecure: bool = False) -> tuple[int, dict, str]:
        """同步 GET（委托共享 webfetch 模块，消除重复逻辑）。"""
        return http_get(url, self._settings.CONNECT_TIMEOUT, insecure)

    async def _fetch_aux(self, netloc: str, scheme: str) -> tuple[list[str], list[str]]:
        """robots.txt / sitemap.xml 各一次 GET（沿用主探测成功的 scheme）。"""
        robots: list[str] = []
        sitemap: list[str] = []
        async with self._limiter.slot():
            _, _, body = await run_sync(self._fetch, f"{scheme}://{netloc}/robots.txt")
        for line in body.splitlines()[:30]:
            if line.lower().startswith("disallow:"):
                robots.append(line.split(":", 1)[1].strip())
        if robots:
            async with self._limiter.slot():
                _, _, body2 = await run_sync(self._fetch, f"{scheme}://{netloc}/sitemap.xml")
            sitemap = re.findall(r"<loc>([^<]+)</loc>", body2)[:10]
        return robots[:10], sitemap


def _apply_headers(headers: dict, findings: dict) -> None:
    """Header 签名匹配 + 版本提取 + 安全头存在性（大小写不敏感，来源强制标注）。"""
    headers_ci = {k.lower(): v for k, v in headers.items()}
    for header, pattern, category, name, conf in HEADER_SIGNATURES:
        value = headers_ci.get(header.lower()) or ""
        if value and re.search(pattern, value, re.I):
            _add(findings, category, name, conf, f"[来源: Header {header}]")
    for header, pattern, category, name in VERSION_HEADER_SIGNATURES:
        value = headers_ci.get(header.lower()) or ""
        match = re.search(pattern, value, re.I)
        if match:
            _add(findings, category, name, 0.9, f"[来源: Header {header}]", version=match.group(1))
    for header, name in SECURITY_HEADER_SIGNATURES:
        if headers_ci.get(header.lower()):
            _add(findings, "安全头", name, 1.0, f"[来源: Header {header} 存在]")


def _apply_body(body: str, findings: dict) -> None:
    """meta generator + 页面特征 + script 版本提取，来源标注 [来源: 页面]。"""
    generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if generator:
        gen_text = generator.group(1)
        version_match = re.search(r"(\d+\.\d+(?:\.\d+)*)", gen_text)
        _add(findings, "generator", gen_text, 0.8, "[来源: meta generator]",
             version=version_match.group(1) if version_match else "")
    for pattern, category, name, conf in BODY_SIGNATURES:
        if re.search(pattern, body, re.I):
            _add(findings, category, name, conf, "[来源: 页面特征]")
    for match in SCRIPT_VERSION_RE.finditer(body):
        _add(findings, "js库", SCRIPT_LIB_NAMES[match.group(1).lower()], 0.9,
             "[来源: 页面 script 版本]", version=match.group(2))


def _add(findings: dict, category: str, name: str, conf: float, source: str, version: str = "") -> None:
    """同类别多来源 → 标注冲突候选（不二选一，交矛盾检测）；同名项补充版本。"""
    item = findings.get(category)
    if item and item["name"] != name:
        item.setdefault("alternatives", []).append({"name": name, "confidence": conf, "source": source})
    elif item is None:
        findings[category] = {"name": name, "confidence": conf, "source": source, "version": version}
    elif version and not item.get("version"):
        item["version"] = version


def _is_ip(host: str) -> bool:
    """判断主机是否为 IP 字面量（IPv4/IPv6）——IP 目标的证书必然与域名不匹配。"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _title(body: str) -> str:
    """提取 <title>。"""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return match.group(1).strip()[:120] if match else ""
