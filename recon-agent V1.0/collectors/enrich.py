"""流水线情报增强编排：Wayback 历史端点 + 子域接管候选检测（全部 L0 只读）。"""
from __future__ import annotations

from output.report import ReconData
from tools.builtin.takeover_check import TakeoverCheckTool, TakeoverParams
from tools.builtin.wayback_urls import WaybackParams, WaybackTool
from utils.config import Settings

MAX_TAKEOVER_HOSTS = 12  # HARD: 接管检测的子域数量上限


async def enrich_recon(data: ReconData, settings: Settings) -> None:
    """在指纹采集后追加历史端点与接管候选两类情报（失败显式记录，不中断）。"""
    from utils.logger import warn

    wayback = await WaybackTool(settings).run(WaybackParams(target=data.target))
    if wayback.success:
        paths = wayback.data.get("paths", [])
        data.notes.append(
            f"历史端点(wayback): {wayback.data.get('count', 0)} 条"
            f"；高频路径: {', '.join(paths[:8]) or '无'}"
        )
    else:
        data.notes.append(f"Wayback 采集失败（不重试）: {wayback.error[:120]}")

    tool = TakeoverCheckTool(settings)
    candidates: list[str] = []
    checked = 0
    for host in data.subdomains[:MAX_TAKEOVER_HOSTS]:
        if host == data.target:
            continue
        result = await tool.run(TakeoverParams(target=host))
        checked += 1
        if result.success and result.data.get("vulnerable"):
            candidates.append(
                f"{result.data['host']} → {result.data['cname']}（{result.data['provider']}）"
            )
    if candidates:
        data.doubts += [f"[接管候选] {c} [未确认，建议人工核实]" for c in candidates]
    data.notes.append(f"接管检测: 检查 {checked} 个子域，候选 {len(candidates)} 个")
