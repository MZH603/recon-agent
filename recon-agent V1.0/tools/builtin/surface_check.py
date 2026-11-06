"""builtin L3 初步脆弱面检查：安全响应头 / TLS 证书有效性 / CORS 反射（单请求级）。

对应用户矩阵流程图最后一环「漏洞初步扫描」——侦察阶段的低扰动实现：
只做单请求级、只读、无利用载荷的检查，发现级输出交由人工或 vuln-verify 定级。

HARD 纪律：
- 每主机 ≤3 请求（基线 GET 1 + CORS 探测 1 + TLS 握手 1），全部只读；
- CORS 探测 Origin 用无效域（*.invalid），无注入意图，仅判定反射；
- 不探测已知 CVE、不发送 payload、不绕过鉴权（那是 vuln-verify 的职责）；
- 扰动控制器熔断即停。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from tools.base import BaseTool, ToolResult
from tools.builtin.fingerprint import split_target
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

# (响应头, 缺失说明, 严重度)
SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("Content-Security-Policy", "无 CSP：XSS 缓解基线缺失", "Low"),
    ("Strict-Transport-Security", "无 HSTS：降级劫持风险", "Low"),
    ("X-Frame-Options", "无 X-Frame-Options：点击劫持风险（CSP frame-ancestors 可替代）", "Low"),
    ("X-Content-Type-Options", "无 X-Content-Type-Options：MIME 嗅探风险", "Info"),
    ("Referrer-Policy", "无 Referrer-Policy：引用泄露风险", "Info"),
    ("Permissions-Policy", "无 Permissions-Policy：敏感 API 未收紧", "Info"),
)
CORS_PROBE_ORIGIN = "https://zm-probe.invalid"


def audit_security_headers(headers: dict) -> tuple[list[dict], list[dict]]:
    """纯函数：响应头 → (缺失项清单, Set-Cookie 标志缺失清单)。"""
    missing = []
    for name, note, severity in SECURITY_HEADERS:
        if not any(k.lower() == name.lower() for k in headers):
            missing.append({"type": "missing_header", "header": name,
                            "note": note, "severity": severity})
    cookie_flag = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            low = v.lower()
            flags = []
            if "secure" not in low:
                flags.append("Secure")
            if "httponly" not in low:
                flags.append("HttpOnly")
            if "samesite" not in low:
                flags.append("SameSite")
            if flags:
                cookie_flag.append({"type": "cookie_flags", "cookie": k,
                                    "missing_flags": flags, "severity": "Medium",
                                    "note": "Cookie 安全标志缺失"})
    return missing, cookie_flag


def classify_cors(status: int, headers: dict) -> dict | None:
    """纯函数：CORS 探测响应 → 反射判定（echo 无效 Origin + credentials = High）。"""
    acao = next((v for k, v in headers.items()
                 if k.lower() == "access-control-allow-origin"), "")
    acac = next((v for k, v in headers.items()
                 if k.lower() == "access-control-allow-credentials"), "")
    if acao == CORS_PROBE_ORIGIN:
        if acac.lower() == "true":
            return {"type": "cors", "severity": "High", "reflected": True,
                    "note": "ACAO 反射任意 Origin 且 allow-credentials=true"
                            "（凭据级跨域暴露，需人工核实）"}
        return {"type": "cors", "severity": "Medium", "reflected": True,
                "note": "ACAO 反射任意 Origin（数据可被任意站点读取）"}
    if acao == "*":
        return {"type": "cors", "severity": "Low", "reflected": False,
                "note": "ACAO 通配符 *（公开资源场景可接受，凭据类接口需核实）"}
    return None


def classify_tls_cert(cert: dict) -> list[dict]:
    """纯函数：证书字段 → 有效性发现（过期/临近过期/自签）。"""
    findings: list[dict] = []
    if not cert:
        return findings
    not_after_raw = cert.get("notAfter")
    subject = dict(cert.get("subject") or ())
    issuer = dict(cert.get("issuer") or ())
    if not_after_raw:
        try:
            not_after = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days = (not_after - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append({"type": "cert_expired", "severity": "Medium",
                                 "note": f"证书已过期 {abs(days)} 天（notAfter={not_after_raw}）"})
            elif days <= 30:
                findings.append({"type": "cert_expiring", "severity": "Info",
                                 "note": f"证书 {days} 天内到期（notAfter={not_after_raw}）"})
        except ValueError:
            findings.append({"type": "cert_parse_fail", "severity": "Info",
                             "note": "notAfter 解析失败（人工核实）"})
    if subject and issuer and subject.get("commonName") == issuer.get("commonName"):
        findings.append({"type": "self_signed", "severity": "Medium",
                         "note": f"自签证书（CN={subject.get('commonName')}）"})
    return findings


class SurfaceCheckParams(BaseModel):
    """初步脆弱面检查参数（单主机，≤3 请求）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机或 host:port")
    check_cors: bool = Field(True, description="CORS Origin 反射探测（1 请求）")
    check_tls: bool = Field(True, description="TLS 证书有效性（1 握手，https 时）")


class SurfaceCheckTool(BaseTool):
    """L3 初步脆弱面检查（安全头/TLS/CORS，单请求级，无 payload）。"""

    name = "surface_check"
    description = ("初步脆弱面检查：安全响应头审计 / TLS 证书有效性 / CORS 反射"
                   "（每主机 ≤3 只读请求，无 payload，L3）")
    risk_level = "中"
    min_level = 3
    params_model = SurfaceCheckParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._disturb: DisturbanceController | None = None

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, SurfaceCheckParams)
        host, port, _ = split_target(params.target)
        netloc = f"{host}:{port}" if port else host
        self._disturb = DisturbanceController(host, self._settings)

        scheme = "https" if (port == 443 or not port) else "http"
        notes: list[str] = []
        findings: list[dict] = []
        missing: list[dict] = []
        cookie_flag: list[dict] = []
        base_status, base_headers = 0, {}
        try:
            # 1) 基线 GET → 安全响应头审计（https 失败换 http，每主机预算内）
            for try_scheme in (scheme, "http") if scheme == "https" else (scheme,):
                async with self._disturb.slot():
                    started = time.monotonic()
                    try:
                        base_status, base_headers, _ = await run_sync(
                            http_get, f"{try_scheme}://{netloc}/",
                            self._settings.CONNECT_TIMEOUT, False, 100_000)
                    except (OSError, ValueError):
                        base_status = 0
                    self._disturb.observe(base_status,
                                          elapsed_ms=(time.monotonic() - started) * 1000)
                if base_status:
                    scheme = try_scheme
                    break
            if base_status == 0:
                return ToolResult.err(self.name, f"无法连接 {netloc}（失败不重试，HARD）")

            missing, cookie_flag = audit_security_headers(base_headers)
            findings += missing + cookie_flag

            # 2) CORS Origin 反射探测（1 请求，无效域）
            if params.check_cors:
                async with self._disturb.slot():
                    try:
                        cors_status, cors_headers, _ = await run_sync(
                            http_get, f"{scheme}://{netloc}/",
                            self._settings.CONNECT_TIMEOUT, False, 20_000,
                            {"Origin": CORS_PROBE_ORIGIN})
                    except (OSError, ValueError):
                        cors_status, cors_headers = 0, {}
                cors = classify_cors(cors_status, cors_headers)
                if cors:
                    findings.append(cors)

            # 3) TLS 证书（https 才做，1 握手）
            if params.check_tls and scheme == "https":
                cert, tls_note = await self._cert_info(host, port or 443)
                if tls_note:
                    notes.append(tls_note)
                findings += classify_tls_cert(cert)
        except DisturbanceSuspendedError as exc:
            notes.append(f"[扰动熔断] {exc} — 检查中止（绝不硬闯）")

        data = {
            "host": netloc, "scheme": scheme, "http": base_status,
            "findings": findings,
            "headers_seen": {k: v[:60] for k, v in list(base_headers.items())[:15]},
            "notes": notes, "disturbance": self._disturb.stats(),
        }
        high = sum(1 for f in findings if f.get("severity") == "High")
        medium = sum(1 for f in findings if f.get("severity") == "Medium")
        return ToolResult(
            name=self.name, success=True, data=data,
            evidence=[f"初步脆弱面: {netloc} 缺失头 {len(missing)}"
                      f"/Cookie 标志 {len(cookie_flag)}（High {high}，Medium {medium}）",
                      "HARD：单请求级只读，无 payload；发现级结果待人工或 vuln-verify 定级"]
                     + notes,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.7 if high else (0.6 if findings else 0.4),
        )

    async def _cert_info(self, host: str, port: int) -> tuple[dict, str]:
        """1 次 TLS 握手读证书（过期/自签判定；失败不重试）。"""

        def _sync() -> dict:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # 自签/不匹配也要读字段
            with socket.create_connection((host, port),
                                          timeout=self._settings.CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return tls.getpeercert(binary_form=False) or {}

        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_sync), timeout=self._settings.CONNECT_TIMEOUT * 2), ""
        except (OSError, ssl.SSLError, ValueError) as exc:
            return {}, f"TLS 证书读取失败: {type(exc).__name__}（不重试）"
