"""builtin 代码仓库泄漏检索（L0 被动：GitHub/Gitee code search + gitleaks 式签名）。

零目标接触：仅查询 GitHub/Gitee 公开搜索 API，不触碰目标基础设施。
HARD 脱敏：任何疑似密钥不落原文（不进 data/evidence/报告/缓存）——
仅存「类型 + 首4字符 + sha256 前12位」，定性必须人工核实。
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse

from pydantic import BaseModel, Field
from typing import Literal

from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

# ---- gitleaks 式密钥签名（捕获组1=密钥本体，用于脱敏；无捕获组=结构性标记）----
# (类型, 正则, 级别)
SECRET_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    (r"AWS Access Key", r"(AKIA[0-9A-Z]{16})", "High"),
    (r"阿里云 AccessKey", r"(LTAI[0-9A-Za-z]{12,})", "High"),
    (r"Google API Key", r"(AIza[0-9A-Za-z_\-]{30,})", "High"),
    (r"Slack Token", r"(xox[baprs]-[A-Za-z0-9\-]{10,})", "High"),
    (r"私钥文件头", r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)", "High"),
    (r"数据库连接串", r"((?:mysql|postgresql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"']{6,})", "High"),
    (r"API Key/Token", r"(?i)(?:api[_-]?key|access[_-]?token)\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{16,})", "High"),
    (r"Secret Key", r"(?i)(?:secret[_-]?key|access[_-]?key[_-]?secret)\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{16,})", "High"),
    (r"疑似口令", r"(?i)(?:password|passwd|pass)\s*[=:]\s*[\"']?([^\s\"']{6,})", "High"),
    (r"JWT 令牌", r"(ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,})", "Medium"),
)

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}

# GitHub code search dork 模板（{domain} 占位）
DORK_TEMPLATES: tuple[str, ...] = (
    '"{domain}" password',
    '"{domain}" secret OR app_secret',
    'filename:.env "{domain}"',
    '"{domain}" jdbc:mysql OR jdbc:postgresql',
    '"{domain}" "BEGIN RSA PRIVATE KEY"',
    '"{domain}" access_key OR access_token',
    '"{domain}" apikey OR api_key',
    '"{domain}" smtp OR mail_host',
)


def mask_secret(value: str) -> str:
    """HARD 脱敏：密钥不落原文——仅首4字符 + sha256 前12位指纹。"""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{value[:4]}***({digest})"


def scan_secret_signatures(text: str) -> list[dict]:
    """纯函数：文本片段 → 脱敏后的密钥命中列表（同类型同指纹去重、按级别排序）。"""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for leak_type, pattern, severity in SECRET_SIGNATURES:
        for match in re.finditer(pattern, text):
            secret = match.group(1) if match.lastindex else match.group(0)
            masked = mask_secret(secret)
            key = (leak_type, masked)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"type": leak_type, "severity": severity, "masked": masked})
    findings.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 9))
    return findings


def build_dorks(domain: str) -> list[str]:
    """纯函数：域名 → dork 查询串列表。"""
    safe = domain.strip()
    return [t.format(domain=safe) for t in DORK_TEMPLATES if safe]


class CodeLeakParams(BaseModel):
    """代码泄漏检索参数（对主域做公开代码搜索，零目标接触）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="主域名（如 example.com）")
    provider: Literal["github", "gitee", "auto"] = "auto"
    max_results: int = Field(20, ge=1, le=30, description="单 dork 结果上限（总预算另受 HARD 常量约束）")


class CodeLeakSearchTool(BaseTool):
    """GitHub/Gitee 代码泄漏检索（L0 被动，第三方 API，不接触目标）。"""

    name = "code_leak_search"
    description = "GitHub/Gitee 公开代码检索：dork 模板 + gitleaks 式签名，疑似密钥脱敏输出（被动 L0）"
    risk_level = "低"
    min_level = 1  # v1.1: L0 已并入 L1（基础侦察）
    params_model = CodeLeakParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, CodeLeakParams)
        github_key = (self._settings.GITHUB_API_KEY or "").strip()
        gitee_key = (self._settings.GITEE_API_KEY or "").strip()
        provider = params.provider
        if provider == "auto":
            provider = "github" if github_key else ("gitee" if gitee_key else "github")
        if provider == "github" and not github_key:
            return ToolResult.err(
                self.name, "GitHub code search 强制认证：请在 config.yaml 配置 GITHUB_API_KEY（PAT，只读即可）")
        if provider == "gitee" and not gitee_key:
            return ToolResult.err(self.name, "Gitee 检索需 GITEE_API_KEY（私人令牌，只读即可）")

        token = github_key if provider == "github" else gitee_key
        dorks = build_dorks(params.target)[: self._settings.CODELEAK_MAX_DORKS]  # HARD 预算
        items: list[dict] = []
        notes: list[str] = []
        queries_run = 0

        for dork in dorks:
            if queries_run >= self._settings.CODELEAK_MAX_DORKS:  # HARD
                break
            queries_run += 1
            status, headers, body = await self._search(dork, provider, token, params.max_results)
            if status == 0:
                notes.append(f"{provider} 查询失败（不重试，HARD）: {dork[:40]}")
                continue
            if status in (401, 403):
                notes.append(f"{provider} 鉴权被拒（HTTP {status}）：检查 token 权限/额度")
                break
            if status == 429 or (provider == "github" and status == 403 and "rate limit" in body.lower()):
                notes.append(f"{provider} 限流（HTTP {status}），提前收敛预算")
                break
            batch = self._parse_hits(body, dork, provider)
            items.extend(batch)

        high_count = sum(
            1 for it in items for f in it.get("secrets", [])
            if f.get("severity") == "High")
        evidence = [
            f"{provider} code search: {params.target}，执行 {queries_run} 个 dork（预算 {self._settings.CODELEAK_MAX_DORKS}）",
            "密钥已脱敏（类型+指纹），原文零落盘（HARD）",
        ]
        if notes:
            evidence.append("; ".join(notes[:3]))
        payload = {"target": params.target, "provider": provider, "items": items,
                   "high_count": high_count, "notes": notes}
        return ToolResult(
            name=self.name,
            success=queries_run > 0,
            data={
                "target": params.target, "provider": provider,
                "queries_run": queries_run, "total_hits": len(items),
                "high_count": high_count, "items": items, "notes": notes,
            },
            evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.75 if high_count else (0.6 if items else 0.4),
        )

    async def _search(self, dork: str, provider: str, token: str,
                      per_page: int) -> tuple[int, dict, str]:
        """单次搜索请求（同步经共享出口；失败收敛 status=0，不重试 HARD）。"""
        import asyncio
        from platforms.sync_worker import run_sync

        if provider == "github":
            url = ("https://api.github.com/search/code?q=" + urllib.parse.quote(dork)
                   + f"&per_page={min(per_page, 20)}")
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.text-match+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        else:  # gitee：能力有限，仅 gist 检索（代码搜索 API 未开放通用检索）
            url = ("https://gitee.com/api/v5/search/gists?q=" + urllib.parse.quote(dork)
                   + f"&per_page={min(per_page, 20)}&access_token={urllib.parse.quote(token)}")
            headers = None
        try:
            return await run_sync(http_get, url, self._settings.CONNECT_TIMEOUT, False,
                                  200_000, headers)
        except (OSError, ValueError):
            return 0, {}, ""

    def _parse_hits(self, body: str, dork: str, provider: str) -> list[dict]:
        """解析搜索响应 → 脱敏条目（纯函数式，异常收敛为空集）。"""
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            return []
        hits = raw.get("items") or []
        out: list[dict] = []
        for hit in hits[: self._settings.CODELEAK_MAX_RESULTS]:
            fragments = " ".join(
                (tm.get("fragment") or "") for tm in (hit.get("text_matches") or []))
            secrets = scan_secret_signatures(fragments)
            if provider == "gitee":  # gist 无 text-match：对标题/正文摘要做一次签名
                secrets = scan_secret_signatures(str(hit.get("title", "")) + fragments)
            out.append({
                "repo": (hit.get("repository") or {}).get("full_name", "") or hit.get("repo", ""),
                "path": hit.get("path", ""),
                "url": hit.get("html_url", ""),
                "dork": dork,
                "secrets": secrets,
                "worst": secrets[0]["severity"] if secrets else "Info",
                "note": "命中 dork，未见密钥特征" if not secrets else "疑似密钥（脱敏，人工核实）",
            })
        return out
