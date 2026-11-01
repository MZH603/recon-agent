"""隐蔽性强制层（HARD：代码层兜底，不依赖 Prompt；LLM 建议的超限参数一律静默修正并审计）。"""
from __future__ import annotations

import asyncio
import ipaddress
import random
from contextlib import asynccontextmanager

from utils.config import Settings, get_settings
from utils.logger import audit

# HARD: 指纹伪装——仅常见浏览器 UA，禁止自定义扫描器标识
BROWSER_UAS: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
)


def random_user_agent() -> str:
    """返回随机常见浏览器 UA。"""
    return random.choice(BROWSER_UAS)


def sanitize_concurrency(n: int) -> int:
    """并发绝对上限 2（HARD：超限静默修正，不报错）。"""
    return max(1, min(int(n), 2))


def enforce_stealth(tool: str, args: list[str], settings: Settings | None = None) -> tuple[list[str], list[str]]:
    """对工具参数做隐蔽性强制修正，返回 (修正后参数, 修正日志)。

    - nmap：剔除禁用扫描类型（-sS/-sU/-A/-sV…）与时序加速模板，补齐 NMAP_ARGS_SAFE；
    - 其他工具：原样透传（限速由 RateLimiter 层强制）。
    """
    return enforce_stealth_level(tool, args, settings, level=0, tier1=False)


def enforce_stealth_level(tool: str, args: list[str], settings: Settings | None = None,
                          level: int = 0, tier1: bool = False) -> tuple[list[str], list[str]]:
    """级别感知修正：L0-L2 行为与历史逐字节一致；仅 L3+逐项确认的 tier1 放行低强度白名单。

    tier1（HARD 仍强制）：仅 NMAP_ARGS_L3_TIER1 白名单；--version-intensity ≤2；
    --max-rate 任何显式声明被覆盖为 L3_SYNSCAN_MAX_RATE；--max-parallelism 恒为 1；
    时序模板仍然禁止。
    """
    s = settings or get_settings()
    if level < 3 or not tier1:
        return _enforce_stealth_base(tool, args, s)
    if tool != "nmap":
        return args, []
    tier1_flags = set(s.NMAP_ARGS_L3_TIER1)
    out: list[str] = []
    corrections: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in tier1_flags:
            out.append(arg)
            if arg == "--version-intensity" and i + 1 < len(args):  # 强度上限 2
                try:
                    intensity = min(int(args[i + 1]), 2)
                except ValueError:
                    intensity = 2
                out.append(str(intensity))
                i += 2
                continue
            i += 1
            continue
        if arg == "--max-rate":  # HARD: 显式速率声明一律被上限覆盖
            i += 2 if (i + 1 < len(args) and args[i + 1].isdigit()) else 1
            continue
        if arg in s.FORBIDDEN_NMAP_ARGS or arg.startswith("-T"):
            corrections.append(f"tier1 白名单外剔除 {arg}")
            i += 1
            continue
        out.append(arg)
        i += 1
    # 强制注入低速率上限（tier1 扫描类型由白名单参数携带，不再注入 -sT）
    if not any(a in tier1_flags for a in out):
        out.insert(0, "-sT")
    for flag, val in (("--max-rate", str(s.L3_SYNSCAN_MAX_RATE)), ("--max-parallelism", "1")):
        if flag not in out:
            out[0:0] = [flag, val]
    if corrections:
        audit("stealth_correction_l3", {"tool": tool, "corrections": corrections})
    return out, corrections


def _enforce_stealth_base(tool: str, args: list[str], s: Settings) -> tuple[list[str], list[str]]:
    """历史 enforce_stealth 主体（L0-L2 行为逐字节不变）。"""
    corrections: list[str] = []
    if tool != "nmap":
        return args, corrections
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in s.FORBIDDEN_NMAP_ARGS:
            corrections.append(f"剔除禁用参数 {arg}（仅允许 TCP Connect，HARD）")
            i += 1
            continue
        if arg.startswith("-T") and len(arg) <= 3:
            corrections.append(f"剔除时序模板 {arg}（加速会提高扰动，HARD）")
            i += 1
            continue
        out.append(arg)
        i += 1
    # 修复（历史 bug）：逐项 insert(0) 会使 SAFE 块顺序倒置（"1" 落到 "--max-rate" 前，
    # nmap 把 "1" 当目标、"-sT" 被 --max-rate 吞掉）。改为整块前插，保持 NMAP_ARGS_SAFE 原序。
    prefix = [safe for safe in s.NMAP_ARGS_SAFE if safe not in out]
    out[0:0] = prefix
    if corrections:
        audit("stealth_correction", {"tool": tool, "corrections": corrections})
    return out, corrections


def normalize_host(target: str) -> str:
    """剥离 scheme/路径/端口，只留主机名或 IP（IPv6 保真、域名尾点归一）。"""
    t = target.strip()
    for prefix in ("https://", "http://"):
        if t.lower().startswith(prefix):
            t = t[len(prefix):]
    t = t.split("/")[0]
    if t.startswith("[") and "]" in t:          # [IPv6]:port → IPv6
        return t[1:t.index("]")]
    if t.count(":") > 1:                        # 裸 IPv6：多冒号整体返回（HARD 保真）
        return t.rstrip(".")
    return t.split(":")[0].rstrip(".")


def allowed_target(target: str, settings: Settings | None = None) -> tuple[bool, str]:
    """目标合规校验。

    HARD 绝对红线（任何模式不可越过）：
    - 受保护 TLD（.gov/.mil）；
    - 链路本地/云元数据地址（169.254.0.0/16）。

    默认拒绝：内网/RFC1918/环回 —— 仅当 LAB_MODE=True（--lab，声明为操作者自有
    实验环境）时放行；政府/军事域名不受 --lab 影响。
    """
    s = settings or get_settings()
    host = normalize_host(target).lower().rstrip(".")
    for tld in s.PROTECTED_TLDS:  # HARD: 绝对红线，任何模式不可越过
        if host == tld.lstrip(".") or host.endswith(tld):
            return False, f"受保护 TLD（{tld}）绝对拒绝"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local:
            return False, "链路本地/云元数据地址绝对拒绝（HARD）"
        # RFC1918 私有地址 + 环回 + 保留地址（二次防线，配合 ip.is_global）
        for prefix in s.RFC1918_RANGES:
            if str(ip).startswith(prefix):
                if not s.LAB_MODE:
                    return False, f"内网/保留地址（{prefix.rstrip('.')}）默认拒绝（自有实验环境请加 --lab）"
                return True, "ok（lab 模式：自有实验目标）"
        if not ip.is_global:
            if not s.LAB_MODE:
                return False, "内网/环回地址默认拒绝（自有实验环境请加 --lab）"
            return True, "ok（lab 模式：自有实验目标）"
    except ValueError:
        if host in ("localhost",):
            if not s.LAB_MODE:
                return False, "localhost 默认拒绝（自有实验环境请加 --lab）"
            return True, "ok（lab 模式：自有实验目标）"
    return True, "ok"


def is_in_scope(candidate: str, main_target: str) -> bool:
    """范围锁定（HARD：仅主域精确匹配及其子域；关联资产一律范围外，代码层硬拦截）。"""
    c = normalize_host(candidate).lower().rstrip(".")
    m = normalize_host(main_target).lower().rstrip(".")
    return c == m or c.endswith("." + m)


class StealthRateLimiter:
    """限速 + 并发控制（HARD：L1/L2 间隔随机 3-10s、并发 ≤2 默认 1，L0 使用礼貌间隔）。"""

    def __init__(self, delay_range: tuple[float, float], concurrency: int = 1) -> None:
        self._delay_range = delay_range
        self._sem = asyncio.Semaphore(sanitize_concurrency(concurrency))

    @asynccontextmanager
    async def slot(self):
        """每次网络触碰都包在 slot() 中：持锁 + 随机延迟，模拟人类节奏。"""
        async with self._sem:
            await asyncio.sleep(random.uniform(*self._delay_range))
            yield
