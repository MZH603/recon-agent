"""报告标准表格渲染：子域名清单 + 存活资产总表（用户指定的标准格式）。"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 避免与 report.py 循环导入
    from output.report import ReconData


def subdomain_section(data: ReconData) -> list[str]:
    """第 2 节：目标下的全部子域名（含存活状态与网络层资产）。"""
    alive = set(data.alive_hosts) or {str(c.get("host", "")) for c in data.tech_cards}
    lines = [f"## 2. 子域名清单（共 {len(data.subdomains)} 个）", ""]
    lines += ["| # | 子域名 | 状态 |", "|---|---|---|"]
    for index, sub in enumerate(sorted(set(data.subdomains)), 1):
        status = "✅ 存活" if sub in alive else "❌ 未解析/未存活"
        lines.append(f"| {index} | {sub} | {status} |")
    lines += ["", f"- 解析 IP: {', '.join(data.ips) or '未检出'}",
              f"- C 段（仅记录）: {', '.join(data.c_sectors) or '未检出'}", ""]
    return lines


def _pick(tech: dict, *categories: str) -> str:
    """按类别顺序取指纹名（带版本），缺失为 —。"""
    parts: list[str] = []
    for category in categories:
        item = tech.get(category)
        if item:
            version = f" v{item['version']}" if item.get("version") else ""
            parts.append(f"{item.get('name', '—')}{version}")
    return " / ".join(parts) or "—"


def asset_table_section(data: ReconData) -> list[str]:
    """第 3 节：存活资产总表——端口/中间件/CMS/语言框架/前端/WAF 一屏呈现。

    行主键 = 存活主机 ∪ 有指纹卡主机（HARD：存活但指纹失败的资产同样必须成行，
    未探测/未检出的字段诚实标注，不省略不填补）。
    """
    lines = ["## 3. 存活资产总表", "",
             "| 资产 | 标题 | 开放端口 | 中间件 | CMS | 语言/框架 | 前端/JS库 | WAF/CDN | 置信度 |",
             "|---|---|---|---|---|---|---|---|---|"]
    cards = {str(c.get("host", "")): c for c in data.tech_cards}
    alive = set(data.alive_hosts) or set(cards)
    # HARD: 指纹失败的资产（error 卡）不属于存活面，留在存疑/降级清单呈现
    hosts = sorted(set(alive) | {h for h, c in cards.items() if not c.get("error")})
    rows = 0
    for host in hosts:
        if not host:
            continue
        card = cards.get(host) or {}
        tech = card.get("tech") or {}
        ports = data.port_map.get(host)
        if ports is None:
            port_cell = "未探测（需 L1 受控扫描）"      # 从未扫描：诚实留白
        elif ports:
            port_cell = ", ".join(str(p) for p in ports)  # 真实扫描结果
        else:
            port_cell = "无开放端口（L1 扫描完成）"       # 扫描完成且无开放端口：明确结论
        confidence = f"{float(card.get('confidence', 0.0)):.1f}" if card else "—"
        title = str(card.get("title", "") or "—")[:28]
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            host, title, port_cell,
            _pick(tech, "middleware"), _pick(tech, "cms"),
            _pick(tech, "language", "framework", "generator"),
            _pick(tech, "frontend", "js库"), _pick(tech, "waf", "cdn"),
            confidence,
        ))
        rows += 1
    if rows == 0:
        lines.append("| （无存活资产数据） | — | — | — | — | — | — | — |")
    lines += ["", "> 端口说明：由探测成功的 scheme 推断（443/HTTPS、80/HTTP）；"
              "完整端口面需 L1 受控扫描（`--profile stealth`）后自动回填。", ""]
    return lines
