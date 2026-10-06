"""被动资产拓线（L0：CRT.sh 子域 / WHOIS / IP 解析；关联资产只记录为范围外候选，绝不扫描）。"""
from __future__ import annotations

import asyncio
import json
import socket
import urllib.request

from security.stealth import normalize_host, random_user_agent
from utils.config import Settings, get_settings
from utils.logger import ok, warn

CT_SOURCES = (  # 证书透明度降级链（HARD：失败不重试，只换源）
    ("crt.sh", "https://crt.sh/?q=%25.{domain}&output=json"),
    ("certspotter", "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dnsnames"),
)
IANA_WHOIS = ("whois.iana.org", 43)


async def expand_assets(target: str, settings: Settings | None = None) -> dict:
    """执行全套被动拓线，返回结构化资产数据（任何单点失败都记为 note，不崩溃）。"""
    settings = settings or get_settings()
    domain = normalize_host(target)
    result: dict = {
        "domain": domain,
        "dns": {},
        "subdomains": [],
        "out_of_scope": [],
        "whois": {},
        "ips": [],
        "c_sectors": [],
        "notes": [],
    }
    result["dns"] = await _collect_dns(domain, settings)
    result["ips"], c_notes = _resolve_ips(domain)
    result["notes"] += c_notes
    result["c_sectors"] = [ip.rsplit(".", 1)[0] + ".0/24" for ip in result["ips"] if "." in ip]
    sub_data = await _crtsh_subdomains(domain, settings)
    result["subdomains"] = sub_data["in_scope"]
    result["out_of_scope"] = sub_data["out_of_scope"]
    result["notes"] += sub_data["notes"]
    result["whois"] = await _whois(domain, settings)
    for sub in result["subdomains"][:8]:
        ok(f"发现子域 {sub} (来源: crt.sh) [被动]")
    for note in result["notes"]:
        warn(note)
    return result


async def _collect_dns(domain: str, settings: Settings) -> dict:
    """并发查询 DNS 全记录（HARD: 仅触碰公共解析器，并发不影响目标）。

    预热首次查询建立解析器记忆 → 其余 4 类型并行（每实例独立限速器）。
    实测：5 类型串行 ~55s → 预热+并行 ~13s。
    """
    from tools.builtin.dns_query import DNSParams, DNSQueryTool

    # 预热：首次查询建立 _LAST_GOOD_RESOLVER 记忆
    warmup = DNSQueryTool(settings)
    warmup_result = await warmup.run(DNSParams(target=domain, rtype="A"))

    records: dict = {}
    if warmup_result.success:
        records["A"] = [r.get("data") for r in warmup_result.data.get("records", [])]
    else:
        records["A"] = []
        records.setdefault("_errors", []).append(f"A: {warmup_result.error[:120]}")

    # 并发查询剩余类型（独立工具实例 → 独立限速器 → 并行）
    async def _query(rtype: str):
        tool = DNSQueryTool(settings)
        result = await tool.run(DNSParams(target=domain, rtype=rtype))
        return rtype, result

    results = await asyncio.gather(*[_query(rt) for rt in ("MX", "NS", "TXT", "SOA")])
    for rtype, result in results:
        if result.success:
            records[rtype] = [r.get("data") for r in result.data.get("records", [])]
        else:
            records[rtype] = []
            records.setdefault("_errors", []).append(f"{rtype}: {result.error[:120]}")
    return records


def _resolve_ips(domain: str) -> tuple[list[str], list[str]]:
    """系统解析 IP + 标注 C 段（HARD：C 段仅记录，永不扫描）。"""
    notes: list[str] = []
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
    except (OSError, UnicodeError) as exc:
        return [], [f"IP 解析失败: {exc}（不重试）"]
    notes += [f"C 段 {ip.rsplit('.', 1)[0]}.0/24 已记录为范围外候选（仅记录不扫描）" for ip in ips[:3]]
    return list(dict.fromkeys(ips))[:10], notes


async def _crtsh_subdomains(domain: str, settings: Settings) -> dict:
    """证书透明度日志查子域（crt.sh → certspotter 降级链）；全部不可达则降级为空并记录。"""
    out: dict = {"in_scope": [], "out_of_scope": [], "notes": []}
    names: set[str] = set()
    used_source = ""
    for source, template in CT_SOURCES:
        try:
            raw = await asyncio.to_thread(_http_get, template.format(domain=domain), 30)
            entries = json.loads(raw)
            used_source = source
            break
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            out["notes"].append(f"CT 源 {source} 不可达（{type(exc).__name__}）")
            entries = []
    if not used_source:
        out["notes"].append(
            "全部 CT 源不可达，子域枚举降级为空；可安装 subfinder 提升召回率"
        )
        return out
    for entry in entries:
        # crt.sh 条目含 name 字段；certspotter 条目含 dnsnames 数组
        names.update(str(n).lower().rstrip(".")
                     for n in (entry.get("dnsnames") or [entry.get("name")]) if n)
    for name in sorted(names)[:200]:
        if not name or "*" in name:
            continue
        if name == domain or name.endswith("." + domain):
            out["in_scope"].append(name)
        else:
            out["out_of_scope"].append(name)  # HARD: 关联资产仅记录为范围外候选
    out["in_scope"] = out["in_scope"][:100]
    out["notes"].append(f"子域来源: {used_source}")
    return out


def _http_get(url: str, timeout: int) -> str:
    """同步 GET（线程池中执行），浏览器 UA 伪装。"""
    req = urllib.request.Request(url, headers={"User-Agent": random_user_agent()})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(1_000_000).decode("utf-8", errors="replace")


async def _whois(domain: str, settings: Settings) -> dict:
    """原生 socket WHOIS（iana → 注册商两级查询），失败显式记录。"""
    try:
        text = await asyncio.to_thread(_whois_query, domain, IANA_WHOIS, settings.CONNECT_TIMEOUT)
        referral = _referral_server(text)
        if referral:
            text = await asyncio.to_thread(
                _whois_query, domain, (referral, 43), settings.CONNECT_TIMEOUT
            )
    except (OSError, UnicodeError) as exc:
        return {"error": f"WHOIS 查询失败: {exc}（不重试）"}
    wanted = ("domain name:", "registrar:", "creation date:", "expiry date:",
              "registrant organization:", "name server:")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith(wanted)]
    return {"raw_lines": lines[:15], "source": "whois(43/tcp)"}


def _whois_query(domain: str, server: tuple[str, int], timeout: int) -> str:
    """单次 WHOIS 查询（socket 43 端口，只读）。"""
    with socket.create_connection(server, timeout=timeout) as sock:
        sock.sendall(f"{domain}\r\n".encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _referral_server(text: str) -> str | None:
    """从 IANA 响应中取注册商 whois 服务器。"""
    for line in text.splitlines():
        if line.lower().startswith("refer:") or line.lower().startswith("whois:"):
            return line.split(":", 1)[1].strip()
    return None

