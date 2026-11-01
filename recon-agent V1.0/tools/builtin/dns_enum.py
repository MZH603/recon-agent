"""builtin L3 DNS 枚举：AXFR 域传送 / 泛解析基线 / 字典爆破 / 子域置换。

HARD 纪律：
- 字典爆破打公共解析器（socket.getaddrinfo），不触碰目标权威 NS（仅 AXFR 尝试连接 NS:53，
  每个 NS 至多 1 次 TCP 连接，符合"不影响目标正常活动"底线）；
- AXFR 成功 = 高危发现（一次拖出全量区域记录），只读记录，不利用；
- 泛解析基线：随机子域先解析，同 IP 命中即过滤假阳性（用户清单要点落地）；
- 全部预算走 Settings（DNS_WORDLIST_L3_CAP / DNS_BRUTE_L3_CONCURRENCY）。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import random
import socket
import struct
from pathlib import Path

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from utils.config import Settings, get_settings

# ---- stdlib DNS 报文（无 dnspython 依赖）----
RTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA"}
AXFR_QTYPE = 252


def encode_name(name: str) -> bytes:
    """域名 → DNS 报文标签序列。"""
    parts = [p for p in name.rstrip(".").split(".") if p]
    if not parts:
        raise ValueError("空域名")
    return b"".join(bytes([len(p)]) + p.encode("ascii", errors="replace") for p in parts) + b"\x00"


def build_query(name: str, qtype: int, qid: int) -> bytes:
    """构造标准查询报文（opcode=QUERY, RD=0；AXFR 必须 RD=0）。"""
    header = struct.pack(">HHHHHH", qid & 0xFFFF, 0x0000, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, 1)  # class=IN


def read_name(buf: bytes, off: int) -> tuple[str, int]:
    """解析（含压缩指针）；返回 (名称, 下一偏移)。"""
    labels: list[str] = []
    jumped = False
    next_off = off
    hops = 0
    while True:
        if off >= len(buf) or hops > 64:
            raise ValueError("报文截断/指针环")
        length = buf[off]
        if length == 0:
            off += 1
            if not jumped:
                next_off = off
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("指针截断")
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                next_off = off + 2
                jumped = True
            off = ptr
            hops += 1
            continue
        labels.append(buf[off + 1:off + 1 + length].decode("ascii", errors="replace"))
        off += 1 + length
    return ".".join(labels), next_off


def decode_rdata(rtype: int, rdata_off: int, rdlen: int, buf: bytes) -> str:
    """按类型解码 RDATA（name 型借用压缩指针上下文）。"""
    rdata = buf[rdata_off:rdata_off + rdlen]
    try:
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(rdata)
        if rtype == 28 and rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (2, 5, 12):
            name, _ = read_name(buf, rdata_off)
            return name
        if rtype == 15 and rdlen >= 3:  # MX: pref(2) + name
            pref = struct.unpack(">H", rdata[:2])[0]
            host, _ = read_name(buf, rdata_off + 2)
            return f"{pref} {host}"
        if rtype == 16:
            out, p = [], 0
            while p < rdlen:
                ln = rdata[p]
                out.append(rdata[p + 1:p + 1 + ln].decode("utf-8", errors="replace"))
                p += 1 + ln
            return " | ".join(out)
        if rtype == 6 and rdlen > 0:  # SOA: mname rname serial...
            mname, off2 = read_name(buf, rdata_off)
            rname, off3 = read_name(buf, off2)
            serial = struct.unpack(">I", buf[off3:off3 + 4])[0] if off3 + 4 <= len(buf) else 0
            return f"{mname} {rname} serial={serial}"
    except (ValueError, struct.error):
        return rdata.hex()[:120]
    return rdata.hex()[:120]


def parse_response_records(buf: bytes) -> tuple[int, list[dict]]:
    """解析应答报文 → (rcode, [{name,type,typename,value}])。"""
    if len(buf) < 12:
        raise ValueError("报文过短")
    _qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0x000F
    off = 12
    for _ in range(qd):
        _, off = read_name(buf, off)
        off += 4
    records: list[dict] = []
    for _ in range(an + ns + ar):
        if off >= len(buf):
            break
        name, off = read_name(buf, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        records.append({
            "name": name, "type": rtype, "typename": RTYPE_NAMES.get(rtype, str(rtype)),
            "value": decode_rdata(rtype, off, rdlen, buf),
        })
        off += rdlen
    return rcode, records


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """精确读 n 字节（EOF 返回 None）。"""
    chunks: list[bytes] = []
    got = 0
    while got < n:
        chunk = sock.recv(n - got)
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def axfr_query(server: str, domain: str, timeout: int = 5) -> tuple[list[dict], str]:
    """对单个 NS 做一次 AXFR 尝试（TCP 53，1 次连接，只读）。

    返回 (记录列表, 错误串)；记录非空且错误为空 = 域传送成功（高危）。
    """
    qid = random.randint(0, 0xFFFF)
    query = build_query(domain, AXFR_QTYPE, qid)
    try:
        with socket.create_connection((server, 53), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack(">H", len(query)) + query)
            records: list[dict] = []
            while True:
                header = recv_exact(sock, 2)
                if not header:
                    break
                (mlen,) = struct.unpack(">H", header)
                if mlen == 0:
                    break
                msg = recv_exact(sock, mlen)
                if msg is None:
                    break
                rcode, recs = parse_response_records(msg)
                if rcode != 0:
                    names = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                             4: "NOTIMP", 5: "REFUSED"}
                    return [], f"rcode={rcode}（{names.get(rcode, 'UNKNOWN')}）"
                records.extend(recs)
                # AXFR 结束：回程再次出现 SOA
                if recs and recs[-1]["type"] == 6 and any(r["type"] == 6 for r in records[:-1]):
                    break
            return records, ""
    except (OSError, ValueError, struct.error) as exc:
        return [], f"{type(exc).__name__}: {exc}"[:120]


# ---- 工具 ----
class DnsEnumParams(BaseModel):
    """L3 DNS 枚举参数。"""

    target: str = Field(..., pattern=r"^[\w\.\-]+$", description="主域名（授权范围内）")
    wordlist_size: int = Field(1000, ge=50, le=5000, description="字典条数上限（HARD cap=DNS_WORDLIST_L3_CAP）")
    try_axfr: bool = Field(True, description="对权威 NS 尝试 AXFR（每个 NS 至多 1 次 TCP 连接）")
    permute: bool = Field(True, description="对已发现子域做环境后缀/前缀变体")


def load_l3_wordlist(cap: int) -> list[str]:
    """加载 L3 字典（tools/data/subnames_l3.txt，cap 截断）。"""
    path = Path(__file__).resolve().parents[1] / "data" / "subnames_l3.txt"
    if not path.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            word = line.strip().lower()
            if word and not word.startswith("#") and word not in seen:
                seen.add(word)
                out.append(word)
            if len(out) >= cap:
                break
    return out


def permute_candidates(subdomains: list[str], domain: str, cap: int) -> list[str]:
    """纯函数：已发现子域 → 环境变体候选（去重、去自身）。"""
    suffixes = ("api", "test", "dev", "uat", "beta", "stg", "staging", "pre", "old", "new", "v2", "2")
    prefixes = ("dev-", "test-", "uat-", "beta-", "staging-", "pre-", "new-", "old-")
    out: list[str] = []
    seen = set(subdomains)
    for sub in subdomains[:20]:
        base = sub.lower().removesuffix("." + domain.lower())
        if not base or "." in base:
            continue
        for sfx in suffixes:
            cand = f"{base}-{sfx}.{domain}"
            if cand not in seen:
                out.append(cand)
        for pfx in prefixes:
            cand = f"{pfx}{base}.{domain}"
            if cand not in seen:
                out.append(cand)
    return out[:cap]


def filter_wildcard(found: dict[str, str], wildcard_ips: set[str]) -> dict[str, str]:
    """纯函数：泛解析 IP 过滤（同 IP 命中视为假阳性）。"""
    if not wildcard_ips:
        return found
    return {host: ip for host, ip in found.items() if ip not in wildcard_ips}


class DnsEnumTool(BaseTool):
    """L3 DNS 枚举（AXFR/泛解析基线/字典/置换）。"""

    name = "dns_enum"
    description = "L3 DNS 枚举：AXFR 域传送（NS:53 各 1 连接）/泛解析基线/字典爆破（公共解析器）/子域置换"
    risk_level = "高"
    min_level = 3
    params_model = DnsEnumParams

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    async def run(self, params: BaseModel) -> ToolResult:
        assert isinstance(params, DnsEnumParams)
        domain = params.target.lower().rstrip(".")
        notes: list[str] = []

        # 1) 泛解析基线（2 个随机子域 → 公共解析器）
        wildcard_ips = await self._wildcard_baseline(domain)
        wildcard = bool(wildcard_ips)

        # 2) AXFR（先 DoH 查 NS，再对每个 NS 至多 1 次 TCP:53）
        axfr_result, axfr_note = ({}, "")
        if params.try_axfr:
            axfr_result, axfr_note = await self._try_axfr(domain)
            if axfr_note:
                notes.append(axfr_note)

        # 3) 字典爆破（公共解析器，并发 DNS_BRUTE_L3_CONCURRENCY）
        words = load_l3_wordlist(min(params.wordlist_size, self._settings.DNS_WORDLIST_L3_CAP))
        found = await self._brute(domain, words)
        if wildcard:
            before = len(found)
            found = filter_wildcard(found, wildcard_ips)
            if before > len(found):
                notes.append(f"泛解析基线过滤 {before - len(found)} 条假阳性")
        alive = {host: ip for host, ip in found.items()}

        # 4) 子域置换（对已发现主机做环境变体解析）
        permuted: dict[str, str] = {}
        if params.permute and alive:
            cands = permute_candidates(sorted(alive) + [domain], domain,
                                       self._settings.DNS_BRUTE_L3_CONCURRENCY * 20)
            permuted = await self._brute_dict({c.split(".")[0]: c for c in cands})
            if wildcard:
                permuted = filter_wildcard(permuted, wildcard_ips)
            permuted = {h: ip for h, ip in permuted.items() if h not in alive}

        all_hosts = sorted(set(alive) | set(permuted))
        data = {
            "target": domain, "wildcard": wildcard, "wildcard_ips": sorted(wildcard_ips),
            "axfr": axfr_result, "wordlist_size": len(words),
            "found": [{"host": h, "ip": alive[h]} for h in sorted(alive)],
            "permuted": [{"host": h, "ip": permuted[h]} for h in sorted(permuted)],
            "total_alive": len(all_hosts), "notes": notes,
        }
        evidence = [
            f"泛解析基线: {'开启（IP=' + ','.join(sorted(wildcard_ips)) + '）' if wildcard else '未检出泛解析'}",
            f"AXFR: {axfr_result.get('verdict', '未尝试')}",
            f"字典爆破: {len(words)} 条 → 存活 {len(alive)}；置换新增 {len(permuted)}",
        ]
        severity_conf = 0.9 if axfr_result.get("vulnerable") else 0.7
        return ToolResult(
            name=self.name, success=True, data=data, evidence=evidence,
            source_hash=hashlib.sha256(
                json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
                .encode("utf-8", errors="replace")).hexdigest()[:64],
            confidence=severity_conf,
        )

    async def _wildcard_baseline(self, domain: str) -> set[str]:
        """两个随机子域均解析成功 → 判定泛解析，收集其 IP 集合。"""
        probes = [f"{self._rnd()}.{domain}", f"{self._rnd()}.{domain}"]
        ips = await asyncio.gather(*[self._resolve(p) for p in probes])
        if all(ips):
            merged: set[str] = set()
            for group in ips:
                merged.update(group)
            return merged
        return set()

    async def _try_axfr(self, domain: str) -> tuple[dict, str]:
        """DoH 查 NS → 每个 NS 一次 AXFR 尝试。"""
        ns_servers = await self._query_ns(domain)
        if not ns_servers:
            return {"attempted": 0, "vulnerable": False, "verdict": "NS 查询失败（不重试）"}, ""
        vulnerable = False
        records: list[dict] = []
        attempts: list[dict] = []
        for ns in ns_servers[:3]:  # HARD: 至多 3 个 NS，每个 1 次 TCP 连接
            recs, err = await asyncio.to_thread(axfr_query, ns.rstrip("."), domain, 5)
            attempts.append({"ns": ns, "error": err or None, "records": len(recs)})
            if recs and not err:
                vulnerable = True
                records = recs[:500]
        verdict = ("域传送成功（AXFR）— 高危：全量区域记录可被拖出，需人工核实"
                   if vulnerable else "AXFR 均被拒绝（正常加固）")
        return {"attempted": len(attempts), "attempts": attempts,
                "vulnerable": vulnerable, "records": records, "verdict": verdict}, ""

    async def _query_ns(self, domain: str) -> list[str]:
        """DoH 查 NS 记录（复用 DNSQueryTool，失败不重试）。"""
        from tools.builtin.dns_query import DNSParams, DNSQueryTool
        result = await DNSQueryTool(self._settings).run(
            DNSParams(target=domain, rtype="NS"))
        if not result.success:
            return []
        return [r.get("data", "") for r in result.data.get("records", [])
                if r.get("type") == "NS" and r.get("data")]

    async def _brute(self, domain: str, words: list[str]) -> dict[str, str]:
        """字典爆破（公共解析器 getaddrinfo，并发受限）。"""
        candidates = {w: f"{w}.{domain}" for w in words}
        return await self._brute_dict(candidates)

    async def _brute_dict(self, candidates: dict[str, str]) -> dict[str, str]:
        """并发解析候选（信号量 DNS_BRUTE_L3_CONCURRENCY，单次超时 4s，无重试）。"""
        sem = asyncio.Semaphore(self._settings.DNS_BRUTE_L3_CONCURRENCY)
        found: dict[str, str] = {}

        async def one(host: str) -> None:
            async with sem:
                ips = await self._resolve(host)
                if ips:
                    found[host] = sorted(ips)[0]

        await asyncio.gather(*[one(h) for h in candidates.values()], return_exceptions=True)
        return found

    async def _resolve(self, host: str) -> set[str]:
        """单次 A 解析（系统解析器，4s 超时，失败收敛空集）。"""
        import asyncio as _aio

        def _sync() -> set[str]:
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            except (OSError, socket.gaierror, UnicodeError):
                return set()
            return {i[4][0] for i in infos}

        try:
            return await _aio.wait_for(_aio.to_thread(_sync), timeout=4.0)
        except _aio.TimeoutError:
            return set()

    @staticmethod
    def _rnd() -> str:
        """随机基线子域（12 位小写字母）。"""
        return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))
