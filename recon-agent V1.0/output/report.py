"""报告生成（HARD：预算耗尽/降级/不完整必须带水印；生成前强制一致性校验）。"""
from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from observability.metrics import TaskMetrics
from output.tables import asset_table_section, subdomain_section
from platforms.paths import get_output_dir

INCOMPLETE_WATERMARK = "[INCOMPLETE] 预算/资源耗尽，结果可能不完整，请勿作为完整结论使用"
DEGRADED_WATERMARK = "[降级模式] 部分结论来自降级实现，置信度已下调"


@dataclass
class ReconData:
    """一次任务的全部结构化产出（报告的唯一数据源）。"""

    target: str
    scan_level: int = 0
    strategy_note: str = "L0 纯被动"
    dns: dict = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[str] = field(default_factory=list)   # 存活解析结果（精准扫描过滤后）
    fp_queue: list[str] = field(default_factory=list)      # 指纹队列（存活优先，礼貌上限在采集器内）
    out_of_scope: list[str] = field(default_factory=list)
    whois: dict = field(default_factory=dict)
    ips: list[str] = field(default_factory=list)
    c_sectors: list[str] = field(default_factory=list)
    port_map: dict = field(default_factory=dict)           # {host: [ports]}（L1 扫描或 scheme 推断）
    notes: list[str] = field(default_factory=list)      # 显式失败/说明
    tech_cards: list[dict] = field(default_factory=list)
    risk_paths: list[dict] = field(default_factory=list)  # L2 枚举命中（{target,path,status,note}）
    cves: list[dict] = field(default_factory=list)
    doubts: list[str] = field(default_factory=list)     # 存疑清单
    degraded: list[str] = field(default_factory=list)   # 降级清单
    next_steps: list[dict] = field(default_factory=list)
    raw_refs: list[str] = field(default_factory=list)
    llm_analysis: str = ""                              # LLM 执行摘要/建议（离线为空）


def render_markdown(data: ReconData, metrics: TaskMetrics, watermarks: list[str]) -> str:
    """渲染 Markdown 报告（结构对齐开发文档 §10）。"""
    lines: list[str] = []
    lines += [f"# Recon 报告 — {data.target}", ""]
    lines += [f"> 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')} · 采集策略: {data.strategy_note}", ""]
    for wm in watermarks:  # HARD: 水印强制置顶
        lines += [f"> ⚠️ **{wm}**", ""]
    lines += ["## 1. 执行摘要", ""]
    if data.llm_analysis:
        lines += [data.llm_analysis, ""]
    lines += [
        f"- 目标 `{data.target}`，扫描级别 L{data.scan_level}",
        f"- 子域命中 {len(data.subdomains)} · IP {len(data.ips)} · 技术栈卡片 {len(data.tech_cards)} · "
        f"CVE 关联 {len(data.cves)}",
        f"- 指标: {metrics.summary()}", "",
    ]
    lines += subdomain_section(data)
    lines += asset_table_section(data)
    lines += ["## 4. 技术栈明细（来源与置信度）", ""]
    if data.tech_cards:
        for card in data.tech_cards:
            lines.append(_tech_card_md(card))
    else:
        lines += ["未检出（见存疑清单与原始数据）", ""]
    if data.risk_paths:
        lines += ["### 风险路径（L2 枚举命中，含泄露嗅探分级）", "",
                  "| 目标 | 路径 | 状态 | 级别 | 判定 |", "|---|---|---|---|---|"]
        for rp in data.risk_paths:
            lines.append(f"| {rp.get('target')} | {rp.get('path')} | {rp.get('status')} |"
                         f" {rp.get('severity', '—')} | {rp.get('note')} |")
        lines.append("")
    lines += ["## 5. 关联资产拓线图", "", "```mermaid", "graph TD"]
    lines.append(f'  T["{data.target}"]')
    tech_by_host: dict[str, str] = {}
    for card in data.tech_cards:
        if card.get("error"):
            continue
        techs = "/".join(v["name"] for v in (card.get("tech") or {}).values()) or "未检出"
        tech_by_host[str(card.get("host", ""))] = techs
    for sub in data.subdomains[:15]:
        if sub == data.target:
            continue
        label = f"{sub}｜{tech_by_host.get(sub, '未指纹')}"
        lines.append(f'  T --> S["{label}"]')
    for out in data.out_of_scope[:6]:
        lines.append(f'  T -. 范围外仅记录 .-> O["{out}"]')
    lines += ["```", "", "范围外候选（仅记录不扫描）:"]
    lines += [f"- {out}" for out in data.out_of_scope] or ["- 无"]
    lines.append("")
    if data.cves:
        lines += ["### CVE 关联（基于确认版本 + 签名快照）", ""]
        for cve in data.cves:
            if cve.get("status") == "found":
                lines.append(f"- {cve.get('product')}: {', '.join(cve.get('cves', [])[:8])} {cve.get('source', '')}")
            else:
                # HARD: 否定证据——未收录/不可用硬输出，禁止编造 CVE 编号
                lines.append(f"- {cve.get('product')}: {cve.get('status')} — {cve.get('note', '')}")
        lines.append("")
    lines += ["## 6. 存疑清单", ""]
    lines += [f"- {d}" for d in (data.doubts or ["无"])] + [""]
    lines += ["## 7. 降级清单", ""]
    lines += [f"- {d}" for d in (data.degraded or ["无（全部使用主实现）"])] + [""]
    lines += ["## 8. 下一步行动建议", ""]
    for step in data.next_steps:
        flag = "⚠️ " if step.get("needs_gate") else ""
        lines.append(
            f"- {flag}`{step.get('command')}` — {step.get('purpose')}"
            f"（风险: {step.get('risk')}"
            + ("，需三级门控确认" if step.get("needs_gate") else "）")
        )
    lines.append("")
    lines += ["## 9. 原始数据引用", ""]
    lines += [f"- {ref}" for ref in (data.raw_refs or ["无"])] + [""]
    if data.notes:
        lines += ["## 附: 采集备注（显式失败记录，未做推测填补）", ""]
        lines += [f"- {n}" for n in data.notes] + [""]
    return "\n".join(lines)


def _tech_card_md(card: dict) -> str:
    """单主机技术栈卡片渲染（每项带 [来源]；字段缺失时安全降级）。"""
    if card.get("error"):
        return f"- **{card.get('host')}**: 探测失败 — {card['error']}"
    lines = [f"- **{card.get('host')}** (HTTP {card.get('status')}, title: {card.get('title') or '-'})"]
    for category, item in (card.get("tech") or {}).items():
        version = f" v{item['version']}" if item.get("version") else ""
        alts = "".join(f" / {a['name']}" for a in item.get("alternatives", []))
        lines.append(
            f"  - {category}: {item.get('name', '?')}{version}{alts}"
            f"（置信度 {item.get('confidence', 0.5):.1f}）{item.get('source', '')}"
        )
    if card.get("robots_hints"):
        lines.append(f"  - robots 线索: {', '.join(card['robots_hints'][:5])}")
    return "\n".join(lines)


def save_report(
    data: ReconData,
    metrics: TaskMetrics,
    watermarks: list[str],
    out_dir: Path | None = None,
) -> dict[str, Path]:
    """保存 Markdown + JSON（始终）与 CSV 资产清单，返回路径表（跨平台 pathlib）。"""
    out_dir = out_dir or get_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() else "_" for c in data.target)
    base = out_dir / f"recon_{safe_target}_{stamp}"

    md_path = base.with_suffix(".md")
    md_path.write_text(render_markdown(data, metrics, watermarks), encoding="utf-8", newline="")

    json_path = base.with_suffix(".json")
    json_path.write_text(
        json.dumps({"report": data.__dict__, "metrics": metrics.model_dump(), "watermarks": watermarks},
                   ensure_ascii=False, indent=2, default=str),
        encoding="utf-8", newline="",
    )

    csv_path = base.with_suffix(".csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "asset", "detail"])
        for sub in data.subdomains:
            writer.writerow(["subdomain", sub, "范围内"])
        for out in data.out_of_scope:
            writer.writerow(["related", out, "范围外候选（仅记录）"])
        for ip in data.ips:
            writer.writerow(["ip", ip, "解析记录"])
        for card in data.tech_cards:
            techs = ";".join(f"{k}={v['name']}" for k, v in (card.get("tech") or {}).items())
            writer.writerow(["tech", card.get("host", ""), techs])
    return {"markdown": md_path, "json": json_path, "csv": csv_path}
