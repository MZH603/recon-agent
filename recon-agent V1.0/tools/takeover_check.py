"""子域名接管检测（L0 只读：CNAME 悬空 + 第三方托管"未部署"特征页匹配）。"""
from __future__ import annotations

import asyncio
import re

from pydantic import BaseModel, Field

from security.stealth import StealthRateLimiter, random_user_agent
from tools.base import BaseTool, ToolResult
from tools.builtin.dns_query import DNSParams, DNSQueryTool
from utils.config import Settings, get_settings

# (第三方托管后缀, "未部署"特征正则, 提供商)——全部为公开常识特征页
TAKEOVER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("github.io", r"there isn'?t a github pages site here", "GitHub Pages"),
    ("herokuapp.com", r"no such app", "Heroku"),
    ("s3.amazonaws.com", r"the specified bucket does not exist|nosuchbucket", "AWS S3"),
    ("cloudfront.net", r"the request could not be satisfied", "CloudFront"),
    ("azurewebsites.net", r"404 web site not found", "Azure Web Apps"),
    ("bitbucket.io", r"repository not found", "Bitbucket"),
    ("ghost.io", r"the thing you were looking for is no longer here", "Ghost(Pro)"),
    ("wordpress.com", r"do you want to register", "WordPress.com"),
    ("netlify.app", r"not found - request id", "Netlify"),
    ("vercel.app", r"the deployment could not be found|deploy_not_found", "Vercel"),
    ("readme.io", r"project doesnt exist… yet|dont exist", "Readme.io"),
)


def match_takeover(body: str) -> str | None:
    """纯函数：响应体匹配接管特征，返回提供商名或 None（便于离线测试）。"""
    for _, marker, provider in TAKEOVER_SIGNATURES:
        if re.search(marker, body, re.I):
            return provider
    return None


class TakeoverParams(BaseModel):
    """接管检测参数（单主机）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$")


class TakeoverCheckTool(BaseTool):
    """悬空 CNAME 接管检测（L0）：DNS 查询 + 单次只读 GET，无利用行为。"""

    name = "takeover_check"
    description = "子域名接管候选检测：CNAME 悬空 + 托管商特征页（只读，L0）"
    risk_level = "低"
    min_level = 0
    params_model = TakeoverParams

    def __init__(self, settings: Settings | None = None, delay_range: tuple[float, float] | None = None) -> None:
        self._settings = settings or get_settings()
        self._limiter = StealthRateLimiter(
            delay_range or self._settings.L0_DELAY_RANGE, self._settings.MAX_CONCURRENCY
        )

    async def run(self, params: BaseModel) -> ToolResult:
        """CNAME → 第三方托管后缀 → 特征页匹配；无 CNAME 即无接管面。"""
        assert isinstance(params, TakeoverParams)
        dns = DNSQueryTool(self._settings)
        result = await dns.run(DNSParams(target=params.target, rtype="CNAME"))
        cnames = [
            str(r.get("data", "")).rstrip(".").lower()
            for r in (result.data or {}).get("records", []) if r.get("data")
        ] if result.success else []
        if not cnames:
            return ToolResult(
                name=self.name, success=True,
                data={"host": params.target, "vulnerable": False, "note": "无 CNAME 记录，无接管面"},
                evidence=[f"DNS CNAME 查询: {params.target} 无别名"], confidence=0.9,
            )
        third_party = [
            c for c in cnames
            if any(c.endswith(suffix) for suffix, _, _ in TAKEOVER_SIGNATURES)
        ]
        if not third_party:
            return ToolResult(
                name=self.name, success=True,
                data={"host": params.target, "vulnerable": False,
                      "note": f"CNAME 指向自管/未识别主机: {', '.join(cnames[:3])}"},
                evidence=[f"CNAME: {', '.join(cnames[:3])}"], confidence=0.8,
            )
        cname = third_party[0]
        provider, body_hit = await self._probe(cname)
        vulnerable = provider is not None
        return ToolResult(
            name=self.name,
            success=True,
            data={"host": params.target, "cname": cname, "provider": provider or "未知",
                  "vulnerable": vulnerable,
                  "note": "悬空接管候选：CNAME 指向可认领的第三方托管" if vulnerable
                          else "CNAME 指向第三方托管但页面未匹配未部署特征"},
            evidence=[f"CNAME {params.target} → {cname}（{provider or '第三方'}）",
                      f"特征页匹配: {'命中' if body_hit else '未命中'}"],
            confidence=0.8 if vulnerable else 0.6,
        )

    async def _probe(self, cname: str) -> tuple[str | None, bool]:
        """对 CNAME 目标各做一次只读 GET（https→http 兜底），匹配特征页。"""
        for scheme in ("https", "http"):
            async with self._limiter.slot():
                try:
                    body = await asyncio.to_thread(self._get, f"{scheme}://{cname}/")
                except (OSError, ValueError):
                    body = ""
                if body:
                    return match_takeover(body), True
        return None, False

    @staticmethod
    def _get(url: str) -> str:
        return http_get_text(url, get_settings().CONNECT_TIMEOUT, max_bytes=50_000)
