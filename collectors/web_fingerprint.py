"""Web 指纹编排（对每个存活主机产出"技术栈卡片"，多源冲突交给矛盾检测模块）。"""
from __future__ import annotations

from tools.builtin.fingerprint import FingerprintParams, FingerprintTool
from utils.config import Settings, get_settings
from utils.logger import ok, warn

MAX_HOSTS = 12  # HARD: L0 阶段对子域指纹探测上限（礼貌节奏，避免批量请求目标）


CONCURRENT_FINGERPRINT = 3  # HARD: 并发指纹主机上限（不同主机并行，每主机仍限速）


async def collect_tech_cards(hosts: list[str], settings: Settings | None = None) -> list[dict]:
    """并发指纹采集（跨主机并行，每主机仍受 L0 限速约束）。

    HARD: 并发仅作用于不同主机（每主机独立工具实例→独立限速器），
    同一主机的请求仍串行限速。总出站速率 ≈ 3 × (1/1.75s) ≈ 1.7 req/s，远低于扫描特征阈值。
    """
    import asyncio

    settings = settings or get_settings()
    sem = asyncio.Semaphore(CONCURRENT_FINGERPRINT)
    cards: list[dict] = []

    async def _one(host: str) -> tuple[str, dict]:
        async with sem:
            tool = FingerprintTool(settings)  # 每主机独立工具 → 独立限速器
            result = await tool.run(FingerprintParams(target=host))
            return host, result

    tasks = [_one(h) for h in hosts[:MAX_HOSTS]]
    for host, result in await asyncio.gather(*tasks):
        if result.success:
            cards.append(result.data)
            techs = ", ".join(
                f"{k}={v['name']}" for k, v in result.data.get("tech", {}).items()
            ) or "未检出"
            ok(f"指纹 {host}: {techs} [被动]")
            for category, item in result.data.get("tech", {}).items():
                for alt in item.get("alternatives", []):
                    warn(f"{host} {category} 冲突: {item['name']} vs {alt['name']} → 需人工核实")
        else:
            cards.append({"host": host, "error": result.error[:160]})
            warn(f"指纹失败 {host}: {result.error[:120]}")
    return cards


def extract_product_versions(cards: list[dict]) -> list[tuple[str, str]]:
    """从卡片中抽取 (产品, 版本) 对，供 CVE 关联（仅取带版本的确定项）。"""
    pairs: list[tuple[str, str]] = []
    for card in cards:
        for item in (card.get("tech") or {}).values():
            name = item.get("name", "")
            version = item.get("version") or ""
            if not version:
                continue
            pairs.append((name.lower(), version))
    return pairs
