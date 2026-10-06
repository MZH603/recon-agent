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
    s = settings or get_settings()
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
    for safe in s.NMAP_ARGS_SAFE:
        if safe not in out:
            out.insert(0, safe)
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
