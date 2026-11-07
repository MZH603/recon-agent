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
    # 评审 P1-7：接管候选主体是「未解析死域」（悬挂 CNAME 场景）——死域优先入检，
    # 并记录每台的 CNAME 判定明细，检测覆盖不再是不透明的「检查了 12 个」。
    alive_set = {str(h) for h in data.alive_hosts}
    dead_first = [s for s in data.subdomains if s != data.target and s not in alive_set]
    alive_rest = [s for s in data.subdomains if s != data.target and s in alive_set]
    checked_hosts: list[str] = []
    for host in (dead_first + alive_rest)[:MAX_TAKEOVER_HOSTS]:
        result = await tool.run(TakeoverParams(target=host))
        checked += 1
        info = result.data or {}
        checked_hosts.append(
            f"{host}→{info.get('cname') or '无CNAME'}"
            + ("[候选]" if info.get("vulnerable") else ""))
        if result.success and info.get("vulnerable"):
            candidates.append(
                f"{info['host']} → {info['cname']}（{info['provider']}）"
            )
    if candidates:
        data.doubts += [f"[接管候选] {c} [未确认，建议人工核实]" for c in candidates]
    data.notes.append(
        f"接管检测: 检查 {checked} 个子域（未解析死域优先 {min(len(dead_first), MAX_TAKEOVER_HOSTS)} 个"
        f"，依据 CNAME→第三方托管后缀→特征页三级指纹），候选 {len(candidates)} 个"
        f"；明细: {'; '.join(checked_hosts[:12])}")
