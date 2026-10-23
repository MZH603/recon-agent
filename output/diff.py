"""报告增量对比（P0-1：与旧报告 JSON 的结构化 diff）。"""
from __future__ import annotations

from output.report import ReconData


def diff_reports(old: dict, new: ReconData) -> str:
    """对比旧报告数据与新任务数据，返回 Markdown 小节（子域/IP/技术栈）。"""
    lines = ["## 增量对比（相对上一份报告）", ""]
    changed = False

    old_subs, new_subs = set(_as_list(old.get("subdomains"))), set(new.subdomains)
    added, removed = sorted(new_subs - old_subs), sorted(old_subs - new_subs)
    if added or removed:
        changed = True
    lines += ["### 子域", f"- 新增({len(added)}): {', '.join(added) or '无'}",
              f"- 消失({len(removed)}): {', '.join(removed) or '无'}", ""]

    old_ips, new_ips = set(_as_list(old.get("ips"))), set(new.ips)
    ip_added, ip_removed = sorted(new_ips - old_ips), sorted(old_ips - new_ips)
    if ip_added or ip_removed:
        changed = True
    lines += ["### 解析 IP", f"- 新增({len(ip_added)}): {', '.join(ip_added) or '无'}",
              f"- 消失({len(ip_removed)}): {', '.join(ip_removed) or '无'}", ""]

    lines.append("### 技术栈")
    old_tech = _tech_map(old.get("tech_cards") or [])
    new_tech = _tech_map(new.tech_cards)
    for host in sorted(set(old_tech) | set(new_tech)):
        before, after = old_tech.get(host, set()), new_tech.get(host, set())
        gained, lost = after - before, before - after
        if gained or lost:
            changed = True
            parts = [f"+{t}" for t in sorted(gained)] + [f"-{t}" for t in sorted(lost)]
            lines.append(f"- {host}: {' '.join(parts)}")
    lines.append("")
    if not changed:
        lines = ["## 增量对比", "", "无实质变化（子域/IP/技术栈均一致）", ""]
    return "\n".join(lines)


def _as_list(value) -> list:
    return [str(v) for v in value] if isinstance(value, list) else []


def _tech_map(cards: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for card in cards:
        if card.get("error"):
            continue
        names = {v.get("name", "") for v in (card.get("tech") or {}).values()}
        out[str(card.get("host", ""))] = {n for n in names if n}
    return out
