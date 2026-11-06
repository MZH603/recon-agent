"""builtin L3 反向 DNS（PTR）：已发现 IP → PTR 记录反查，寻找关联资产。

对应用户矩阵第一阶段「反向 DNS 解析：对目标 IP 段进行反向查询，寻找关联资产」。

HARD 纪律：
- 全部查询打公共 DoH（dns.google / alidns），零目标基础设施接触（扰动=0）；
- 输入 IP 仅限侦察过程中已发现的授权范围 IP（被动解析 IP / 端口面主机 IP /
  源站候选），禁止对任意 C 段做批量 PTR（范围外资产不触碰）；
- cap=PTR_L3_CAP；单 IP 失败不重试。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from platforms.sync_worker import run_sync

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from tools.builtin.webfetch import http_get
from utils.config import Settings, get_settings

DOH_ENDPOINTS: tuple[str, ...] = (
    "https://dns.google/resolve?name={name}&type=PTR",
    "https://dns.alidns.com/resolve?name={name}&type=PTR",
)


def build_ptr_name(ip: str) -> str:
    """纯函数：IPv4 → in-addr.arpa 反查名（非法 IP 返回空串）。"""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return ""
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return ""
    if any(o < 0 or o > 255 for o in octets):
        return ""
    return ".".join(str(o) for o in reversed(octets)) + ".in-addr.arpa"


def extract_ptr(payload: dict) -> list[str]:
    """纯函数：DoH JSON → PTR 主机名列表（相对名补尾点剔除）。"""
    out: list[str] = []
    for answer in payload.get("Answer") or []:
        if answer.get("type") == 12 and answer.get("data"):
            name = str(answer["data"]).rstrip(".").lower()
            if name and name not in out:
                out.append(name)
    return out


def in_scope_hit(ptr_names: list[str], domain: str) -> list[str]:
    """纯函数：PTR 命中授权主域（含子域）的记录 → 关联资产候选。"""
    dom = domain.lower().rstrip(".")
    return [n for n in ptr_names if n == dom or n.endswith("." + dom)]


class ReverseDnsParams(BaseModel):
    """反向 DNS 参数（IP 仅限已发现的授权范围内地址）。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="授权主域名（用于判定 in-scope 命中）")
    ips: list[str] = Field(..., min_length=1, max_length=200,
                           description="待反查 IP（侦察过程中已发现；禁止任意 C 段批量）")


class ReverseDnsTool(BaseTool):
    """L3 反向 DNS（PTR 反查，DoH 公共解析器，零目标接触）。"""

    name = "reverse_dns"
    description = "已发现 IP 的 PTR 反查（DoH 公共解析器，零目标接触），PTR 命中主域 = 关联资产（L3）"
    risk_level = "低"
    min_level = 3
    params_model = ReverseDnsParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, ReverseDnsParams)
        domain = params.target.lower().rstrip(".")
        ips = list(dict.fromkeys(params.ips))[: self._settings.PTR_L3_CAP]  # HARD cap
        notes: list[str] = []

        sem = asyncio.Semaphore(4)

        async def one(ip: str) -> tuple[str, list[str]] | None:
            name = build_ptr_name(ip)
            if not name:
                return None
            async with sem:
                for tpl in DOH_ENDPOINTS:  # 降级链：失败换源，不重试同源
                    try:
                        status, _, body = await run_sync(
                            http_get, tpl.format(name=name),
                            self._settings.CONNECT_TIMEOUT, False, 50_000)
                        if status == 200:
                            ptrs = extract_ptr(json.loads(body))
                            return (ip, ptrs)
                    except (OSError, ValueError, json.JSONDecodeError):
                        continue
            return None

        raw = await asyncio.gather(*[one(ip) for ip in ips], return_exceptions=True)
        ptr_map: dict[str, list[str]] = {}
        for item in raw:
            if isinstance(item, tuple):
                ptr_map[item[0]] = item[1]
        if len(ptr_map) < len(ips):
            notes.append(f"{len(ips) - len(ptr_map)} 个 IP 查询失败（不重试，HARD）")

        hits = {ip: in_scope_hit(names, domain)
                for ip, names in ptr_map.items() if in_scope_hit(names, domain)}
        data = {
            "target": domain,
            "ips_queried": len(ips),
            "ptr_resolved": {ip: names for ip, names in ptr_map.items() if names},
            "ptr_count": sum(len(n) for n in ptr_map.values()),
            "in_scope_hits": {ip: names for ip, names in hits.items() if names},
            "notes": notes,
        }
        evidence = [
            f"反向 DNS: {len(ips)} IP → {data['ptr_count']} 条 PTR（DoH 公共解析器，零目标接触）",
            f"授权域命中 {len(data['in_scope_hits'])} 个（关联资产候选，仅记录）",
        ] + notes
        return ToolResult(
            name=self.name, success=True, data=data, evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=0.6 if ptr_map else 0.3,
        )
