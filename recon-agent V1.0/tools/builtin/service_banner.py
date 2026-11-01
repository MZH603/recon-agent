"""builtin L3 服务识别：TCP Connect + banner 抓取（替代被禁 nmap -sV 的 tier0 手段）。

HARD：每端口 1 次连接、只收不发（SSH/FTP/SMTP/POP3/IMAP/MySQL 等主动问候类服务
免指令识别）；HTTP 类端口无 banner 时按端口语义标注 [待确认]；
每主机 ≤20 端口；经扰动控制器自适应节流。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import socket

from pydantic import BaseModel, Field

from security.disturbance import DisturbanceController, DisturbanceSuspendedError
from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings

# (名称, banner 正则, 置信度)
BANNER_SIGNATURES: tuple[tuple[str, str, float], ...] = (
    ("SSH", r"SSH-[\d\.]+-(\S+)", 0.9),
    ("FTP", r"220[ -].*(?:FTP|ftp)", 0.85),
    ("SMTP", r"220[ -].*(?:SMTP|ESMTP|Postfix|Exim|mail)", 0.85),
    ("POP3", r"\+OK.*(?:POP3|pop)", 0.9),
    ("IMAP", r"\* OK.*(?:IMAP|imap)", 0.9),
    ("MySQL", r"(?:mysql|MariaDB)", 0.8),
    ("Redis", r"-ERR|ERR unknown command", 0.7),
    ("Memcached", r"ERROR", 0.3),
    ("VNC", r"RFB \d+\.\d+", 0.9),
    ("Telnet", r"(?:login:|Password:)", 0.7),
)
PORT_HINTS = {80: "HTTP?", 443: "HTTPS?", 8080: "HTTP-alt?", 8443: "HTTPS-alt?",
              3389: "RDP?", 3306: "MySQL?", 5432: "PostgreSQL?", 6379: "Redis?",
              9200: "Elasticsearch?", 22: "SSH?", 25: "SMTP?"}


def classify_banner(banner: str, port: int) -> dict:
    """纯函数：banner 文本 → 服务判定（无 banner 时按端口语义给 [待确认] 提示）。"""
    text = (banner or "").strip()
    for name, pattern, conf in BANNER_SIGNATURES:
        match = re.search(pattern, text, re.I)
        if match:
            version = match.group(1) if match.groups() and match.group(1) else ""
            return {"service": name, "confidence": conf, "version": version[:40],
                    "banner": text[:120]}
    if text:
        return {"service": "unknown", "confidence": 0.3, "version": "",
                "banner": text[:120]}
    return {"service": PORT_HINTS.get(port, "no-banner"), "confidence": 0.2,
            "version": "", "banner": ""}


class ServiceBannerParams(BaseModel):
    """服务识别参数（单主机，端口 ≤20）。"""

    target: str = Field(..., pattern=r"^[\w\.\-/:]+$", description="目标主机/IP")
    ports: list[int] = Field(..., min_length=1, max_length=20,
                             description="待识别端口（来自 L1/L3 端口扫描的开放面）")


class ServiceBannerTool(BaseTool):
    """L3 服务识别（banner 抓取，每端口 1 连接，只收不发）。"""

    name = "service_banner"
    description = "TCP Connect + banner 抓取识别服务（替代 -sV；每端口 1 连接，只收不发，扰动极小）"
    risk_level = "中"
    min_level = 3
    params_model = ServiceBannerParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._disturb: DisturbanceController | None = None

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, ServiceBannerParams)
        self._disturb = DisturbanceController(params.target, self._settings)
        results: list[dict] = []
        notes: list[str] = []
        try:
            for port in params.ports[:20]:
                banner, ok = await self._grab(params.target, port)
                entry = {"port": port, "reachable": ok}
                entry.update(classify_banner(banner, port))
                results.append(entry)
                self._disturb.observe(200 if ok else 0, elapsed_ms=0)
        except DisturbanceSuspendedError as exc:
            notes.append(f"[扰动熔断] {exc}")
        data = {
            "target": params.target,
            "probed": len(results),
            "services": results,
            "disturbance": self._disturb.stats(),
            "notes": notes,
        }
        identified = [r for r in results if r.get("confidence", 0) >= 0.7]
        return ToolResult(
            name=self.name,
            success=bool(results) and not notes,
            data=data,
            evidence=[f"banner 识别: {params.target} 共 {len(results)} 端口，高置信 {len(identified)}",
                      "只收不发（免指令识别），每端口 1 次连接（HARD）"]
                      + notes,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.7 if identified else 0.4,
        )

    async def _grab(self, host: str, port: int) -> tuple[str, bool]:
        """单端口 banner 抓取（1 连接，2s 读超时；失败/超时返回空）。"""

        def _sync() -> tuple[str, bool]:
            try:
                with socket.create_connection((host, port), timeout=self._settings.CONNECT_TIMEOUT) as s:
                    s.settimeout(2.0)
                    try:
                        data = s.recv(128)
                    except (socket.timeout, OSError):
                        data = b""
                    return data.decode("utf-8", errors="replace"), True
            except OSError:
                return "", False

        async with self._disturb.slot():
            return await asyncio.to_thread(_sync)
