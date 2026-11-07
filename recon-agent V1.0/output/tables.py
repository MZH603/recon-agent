"""报告标准表格渲染：子域名清单 + 存活资产总表（用户指定的标准格式）。"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 避免与 report.py 循环导入
    from output.report import ReconData


def subdomain_section(data: ReconData) -> list[str]:
    """第 2 节：目标下的全部子域名（三态存活语义，评审 P0-2）。

    三态定义（HARD：不得混用，可解析 ≠ 服务存活）：
    - ✅ 端口确认 = L1 端口扫描有开放端口（最强证据）
    - 🌐 HTTP 可达 = 指纹卡成功（HTTP 层有响应），端口面未必扫全
    - · 可解析 = 仅 DNS 解析成功，HTTP/端口层未确认
    - ❌ 未解析 = DNS 解析失败
    """
    alive = set(data.alive_hosts)
    http_ok = set(data.http_reachable) | {
        str(c.get("host", "")) for c in data.tech_cards if not c.get("error")}
    port_ok = {h for h, ports in (data.port_map or {}).items() if ports}
    lines = [f"## 2. 子域名清单（共 {len(data.subdomains)} 个）", ""]
    lines += ["| # | 子域名 | 状态 |", "|---|---|---|"]
    for index, sub in enumerate(sorted(set(data.subdomains)), 1):
        if sub in port_ok:
            status = "✅ 端口确认"
        elif sub in http_ok:
            status = "🌐 HTTP 可达"
        elif sub in alive:
            status = "· 可解析"
        else:
            status = "❌ 未解析"
        lines.append(f"| {index} | {sub} | {status} |")
    lines += ["", f"- 解析 IP: {', '.join(data.ips) or '未检出'}",
              f"- C 段（仅记录，见第 5 节）: {', '.join(data.c_sectors) or '未检出'}",
              "- 状态口径: ✅=端口扫描有开放端口；🌐=HTTP 层有响应；·=仅 DNS 解析；"
              "❌=解析失败。**可解析 ≠ 服务存活**。", ""]
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
            port_cell = "未探测"                       # 从未扫描：诚实留白
        elif ports:
            port_cell = ", ".join(str(p) for p in ports)  # 真实扫描结果
        else:
            port_cell = "无开放端口"                    # 扫描完成且无开放端口：明确结论
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
    lines += ["", f"> 端口扫描范围: {data.port_scan_scope or '未记录'}。"
              "「无开放端口」= 上述范围内无开放；不代表全端口面结论。"
              "由探测成功的 scheme 推断的端口（443/HTTPS、80/HTTP）与扫描结果合并呈现。", ""]
    return lines
