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
    strategy_note: str = "L1 基础侦察（被动采集 + 隐蔽端口）"
    authorization_note: str = ""                           # 授权依据（--note，审计同源）
    scan_window: str = ""                                  # 采集窗口（开始—结束时间）
    port_scan_scope: str = ""                              # 端口扫描范围声明（已扫端口清单）
    dns: dict = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[str] = field(default_factory=list)   # 可解析主机（DNS 层存活；≠端口/HTTP 确认）
    http_reachable: list[str] = field(default_factory=list)  # HTTP 层可达主机（有指纹卡或 scheme 证据）
    fp_queue: list[str] = field(default_factory=list)      # 指纹队列（存活优先，礼貌上限在采集器内）
    out_of_scope: list[str] = field(default_factory=list)
    whois: dict = field(default_factory=dict)
    ips: list[str] = field(default_factory=list)
    c_sectors: list[str] = field(default_factory=list)
    port_map: dict = field(default_factory=dict)           # {host: [ports]}（L1 扫描或 scheme 推断）
    notes: list[str] = field(default_factory=list)      # 显式失败/说明
    tech_cards: list[dict] = field(default_factory=list)
    risk_paths: list[dict] = field(default_factory=list)  # L2 枚举命中（{target,path,status,note}）
    api_endpoints: list[dict] = field(default_factory=list)
    frontend_routes: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)
    workspace_notes: list[dict] = field(default_factory=list)
    threat_models: list[dict] = field(default_factory=list)
    cves: list[dict] = field(default_factory=list)
    # ---- 情报扩容（L0 被动，第三方平台；collectors/intel_expander.py 填充）----
    mapping_assets: list[dict] = field(default_factory=list)  # 测绘引擎资产
    org_info: dict = field(default_factory=dict)              # 邮箱/ICP/ASN/企业
    code_leaks: list[dict] = field(default_factory=list)      # 代码泄漏（密钥已脱敏）
    dork_findings: list[dict] = field(default_factory=list)   # 搜索引擎 dorking
    l3_results: list[dict] = field(default_factory=list)      # L3 深度侦察结构化结果（tool/host/data）
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
    lines += ["## 0. 授权与范围声明", ""]
    lines += [
        f"- 授权目标: `{data.target}`（级别 L{data.scan_level}）",
        f"- 授权依据: {_table_cell(data.authorization_note) or '（未提供 --note，见审计日志 cascade_authorization）'}",
        f"- 采集窗口: {_table_cell(data.scan_window) or time.strftime('%Y-%m-%d %H:%M:%S')}",
        "- 范围边界: 仅上表范围内资产；C 段/关联域只记录不扫描（HARD）；"
        "发现级输出需人工或授权验证流程定级",
        "",
    ]
    lines += ["## 1. 执行摘要", ""]
    if data.llm_analysis:
        lines += [data.llm_analysis, ""]
    # CVE 口径：无关联时必须说明原因（缺版本指纹 ≠ 0 个漏洞）
    cve_note = ""
    if not data.cves:
        has_unversioned = any(
            (c.get("tech") or {}).get("server") and not (c.get("tech") or {}).get("server", {}).get("version")
            for c in data.tech_cards if not c.get("error"))
        cve_note = "（无法映射：中间件未暴露版本指纹）" if has_unversioned else ""
    lines += [
        f"- 目标 `{data.target}`，扫描级别 L{data.scan_level}",
        f"- 子域命中 {len(data.subdomains)} · IP {len(data.ips)} · 技术栈卡片 {len(data.tech_cards)} · "
        f"CVE 关联 {len(data.cves)}{cve_note}",
        f"- 指标: {metrics.summary()}", "",
    ]
    lines += subdomain_section(data)
    lines += asset_table_section(data)
    lines += _dns_records_section(data)
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
    if data.api_endpoints:
        lines += ["### JS/API 端点（静态候选与运行时观测）", "",
                  "| 方法 | 路径 | 参数线索 | 状态 | 来源 |", "|---|---|---|---|---|"]
        for endpoint in data.api_endpoints:
            status = "已观测请求（未证明可访问）" if endpoint.get('observed') else "候选（未验证）"
            cells = [endpoint.get('method') or '未知', endpoint.get('path', ''),
                     ', '.join(map(str, endpoint.get('params') or [])), status, endpoint.get('source', '')]
            lines.append('| ' + ' | '.join(_table_cell(cell) for cell in cells) + ' |')
        lines.append('')
    if data.frontend_routes:
        lines += ["### 前端路由线索", ""]
        lines += ['- ' + _table_cell(route) for route in data.frontend_routes] + ['']
    if data.findings:
        labels = {'candidate': '候选（未验证）', 'observed': '已观测（待复核）', 'verified': '验证声明（证据仍需复核）'}
        lines += ['### 发现记录', '', '| 标题 | 级别 | 状态 | 证据/来源 |', '|---|---|---|---|']
        for item in data.findings:
            values = [item.get('title', item.get('url', '')), item.get('severity', 'info'),
                labels.get(item.get('status'), '候选（未验证）'), ', '.join(item.get('evidence_ids', [])) or item.get('source', '')]
            lines.append('| ' + ' | '.join(_table_cell(v) for v in values) + ' |')
        lines.append('')
    if data.coverage:
        lines += ['### 覆盖记录', '', '| 面 | 风险类别 | 结果 | 说明 |', '|---|---|---|---|']
        for item in data.coverage:
            lines.append('| ' + ' | '.join(_table_cell(item.get(key, '')) for key in ('surface', 'risk_area', 'outcome', 'content')) + ' |')
        lines.append('')
    for title, records in (('会话笔记', data.workspace_notes), ('威胁模型', data.threat_models)):
        if records:
            lines += ['### ' + title, '']
            lines += ['- ' + _table_cell(item.get('title', '')) + ': ' + _table_cell(item.get('content', '')) for item in records] + ['']
    lines += _l3_results_section(data)
    lines += _intel_expansion_section(data)
    lines += ["## 5. 关联资产拓线图", "", "```mermaid", "graph TD"]
    lines.append(f'  T["{data.target}"]')
    tech_by_host: dict[str, str] = {}
    favicon_by_host: dict[str, str] = {}
    for card in data.tech_cards:
        if card.get("error"):
            continue
        techs = "/".join(v["name"] for v in (card.get("tech") or {}).values()) or "未检出"
        host = str(card.get("host", ""))
        tech_by_host[host] = techs
        if card.get("favicon_md5"):
            favicon_by_host[host] = str(card["favicon_md5"])
    # 已指纹主机优先展示（评审：拓线图曾把已指纹主机截断为「未指纹」）
    ordered = ([h for h in tech_by_host if h != data.target]
               + [s for s in data.subdomains if s != data.target and s not in tech_by_host])
    seen: set[str] = set()
    shown = 0
    for sub in ordered:
        if sub in seen or shown >= 25:
            continue
        seen.add(sub)
        shown += 1
        label = f"{sub}｜{tech_by_host.get(sub, '未指纹')}"
        lines.append(f'  T --> S["{label}"]')
    # favicon 同值聚类边（跨主机同 md5 = 同源部署线索）
    clusters: dict[str, list[str]] = {}
    for host, md5 in favicon_by_host.items():
        clusters.setdefault(md5, []).append(host)
    for md5, hosts in clusters.items():
        if len(hosts) > 1:
            anchor = hosts[0]
            for peer in hosts[1:]:
                lines.append(f'  S["{anchor}｜{tech_by_host.get(anchor, "未指纹")}"] -. favicon 同源 .-> S["{peer}｜{tech_by_host.get(peer, "未指纹")}"]')
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


def _table_cell(value) -> str:
    return str(value).replace('\n', ' ').replace('\r', ' ').replace('|', r'\|').replace('`', r'\`')


def _dns_records_section(data: ReconData) -> list[str]:
    """3b 节：DNS 记录面（A/AAAA/MX/NS/TXT/SOA + SPF/DMARC 解析）。

    评审缺口：mx1-3 是 MX 服务器却无 SPF/DMARC/NS 记录呈现——邮件伪造面与
    名称服务器拓扑对评估直接相关，缺失即渲染「未检出」，不做推测填补。
    """
    dns = data.dns or {}
    if not dns:
        return []
    lines: list[str] = ["## 3b. DNS 记录面（公共解析器查询）", ""]
    for rtype in ("A", "AAAA", "MX", "NS", "SOA"):
        values = dns.get(rtype) or []
        lines.append(f"- {rtype}: " + (", ".join(_table_cell(v) for v in values[:8]) or "未检出")
                     + (f"（共 {len(values)} 条）" if len(values) > 8 else ""))
    txt = dns.get("TXT") or []
    lines.append(f"- TXT: " + ("; ".join(_table_cell(v) for v in txt[:6]) or "未检出"))
    spf = [v for v in txt if str(v).lower().startswith("v=spf1")]
    dmarc = dns.get("DMARC") or []
    lines.append("- SPF: " + ("; ".join(_table_cell(v) for v in spf) or "未检出（无 v=spf1 TXT）——邮件伪造面需人工评估"))
    lines.append(f"- DMARC: " + ("; ".join(_table_cell(v) for v in dmarc) or "未检出（_dmarc 无记录）"))
    for err in dns.get("_errors") or []:
        lines.append(f"- 查询失败: {_table_cell(err)}")
    lines.append("")
    return lines


def _l3_results_section(data: ReconData) -> list[str]:
    """4c 节：L3 深度侦察结构化结果——目录/参数/文档/脆弱面全量渲染。

    评审 P0：此前 dir_enum_deep 只落一行计数、param_mining JSON 截断在
    builder.add_note（400 字符）——本节以完整表格呈现全部发现。
    """
    if not data.l3_results:
        return []
    lines: list[str] = ["## 4c. L3 深度侦察结果（全量，发现级待人工定级）", ""]
    by_tool: dict[str, list[dict]] = {}
    for item in data.l3_results:
        by_tool.setdefault(item.get("tool", ""), []).append(item)

    dir_items = by_tool.get("dir_enum_deep", [])
    if dir_items:
        lines += ["### 深度目录枚举（软404 基线差分后命中）", "",
                  "| 主机 | 路径 | 状态 | 级别 | 判定 |", "|---|---|---|---|---|"]
        for item in dir_items:
            found = (item.get("data") or {}).get("found") or []
            if not found:
                lines.append(f"| {item.get('host')} | （{ (item.get('data') or {}).get('checked', 0)} 路径零命中） | — | — | 正面项 |")
                continue
            for f in found:
                lines.append("| {} | {} | {} | {} | {} |".format(
                    _table_cell(item.get("host")), _table_cell(f.get("path", "")),
                    _table_cell(f.get("status", "")), _table_cell(f.get("severity", "—")),
                    _table_cell(f.get("note", ""))[:160]))
        lines.append("")

    param_items = by_tool.get("param_mining", [])
    if param_items:
        lines += ["### 参数挖掘（marker 反射 + 基线差分）", "",
                  "| 主机 | 参数 | 状态 | 反射 | 差分 | 判定 |", "|---|---|---|---|---|---|"]
        for item in param_items:
            findings = (item.get("data") or {}).get("findings") or []
            if not findings:
                lines.append(f"| {item.get('host')} | （{(item.get('data') or {}).get('checked', 0)} 参数无激活） | — | — | — | 正面项 |")
                continue
            for f in findings:
                lines.append("| {} | {} | {} | {} | {} | {} |".format(
                    _table_cell(item.get("host")), _table_cell(f.get("param", "")),
                    _table_cell(f.get("status", "")), "是" if f.get("reflected") else "否",
                    _table_cell(f.get("verdict", "")), _table_cell(f.get("note", ""))[:120]))
        lines.append("")

    for tool_name, header in (("api_doc_probe", "API 文档/未授权面探测"),
                              ("surface_check", "初步脆弱面（安全头/TLS/CORS）"),
                              ("service_banner", "服务 Banner 识别"),
                              ("reverse_dns", "反向 DNS（PTR）"),
                              ("alive_os_probe", "存活探测 + OS 启发式"),
                              ("topology_trace", "拓扑追踪"),
                              ("origin_hunt", "CDN/源站线索"),
                              ("vhost_scan", "虚拟主机差分"),
                              ("cloud_enum", "云存储枚举"),
                              ("dns_enum", "DNS 深度枚举")):
        items = by_tool.get(tool_name, [])
        if not items:
            continue
        lines += [f"### {header}", ""]
        for item in items:
            payload = json.dumps(item.get("data") or {}, ensure_ascii=False, default=str)
            lines.append(f"- **{item.get('host') or item.get('target')}**: {_table_cell(payload)[:1500]}")
        lines.append("")
    return lines


def _intel_expansion_section(data: ReconData) -> list[str]:
    """情报扩容章节（L0 第三方平台）：测绘引擎/组织人员/代码泄漏/dorking。

    未启用的通道显式声明原因（未配置 Key），不静默留空（HARD：不编造）。
    """
    lines: list[str] = ["## 4b. 情报扩容（外部平台，L0 被动）", ""]

    lines += ["### 测绘引擎资产面", ""]
    if data.mapping_assets:
        lines += ["| 来源 | 类型 | 资产 | 端口/协议 | 标题/组件 |", "|---|---|---|---|---|"]
        for a in data.mapping_assets[:30]:
            lines.append("| " + " | ".join(_table_cell(a.get(k, "")) for k in
                                           ("source", "type", "value", "port", "title")) + " |")
        lines.append("")
    else:
        lines += ["未启用或无产出（缺 API Key，见采集备注）", ""]

    lines += ["### 组织与人员情报", ""]
    org = data.org_info
    if org:
        if org.get("whois_org"):
            lines.append(f"- 注册组织: {_table_cell(org['whois_org'])}（来源: WHOIS）")
        if org.get("emails"):
            lines.append("- 邮箱: " + ", ".join(
                _table_cell(e.get("email", ""))
                + (f"（{e.get('source')}）" if "注册局" in str(e.get("source", "")) else "")
                for e in org["emails"][:10]))
        else:
            lines.append("- 邮箱: 未检出（主站/WHOIS 均未暴露）")
        if org.get("role_account_candidates"):
            lines.append("- 角色账号候选 [未确认]: " + ", ".join(org["role_account_candidates"]))
        icp = org.get("icp") or {}
        lines.append(f"- ICP 备案: {_table_cell(icp.get('status', 'skipped'))}"
                     + (f" — {_table_cell(str(icp.get('reason', ''))[:120])}" if icp.get("reason") else ""))
        for entry in (org.get("asn") or [])[:3]:
            lines.append(f"- ASN: {_table_cell(entry.get('ip', ''))} → {_table_cell(entry.get('asn', ''))}"
                         + (f"（{entry.get('error', '')}）" if entry.get("error") else ""))
        lines.append("")
    else:
        lines += ["未启用", ""]

    lines += ["### 代码泄漏面（密钥已脱敏，定性需人工核实）", ""]
    if data.code_leaks:
        lines += ["| 仓库 | 路径 | 最高级别 | 密钥类型（脱敏指纹） |", "|---|---|---|---|"]
        for item in data.code_leaks[:20]:
            types = ", ".join(
                f"{s.get('type')}({s.get('masked', '')})" for s in item.get("secrets", [])) or "—"
            lines.append("| " + " | ".join(_table_cell(v) for v in (
                item.get("repo", ""), item.get("path", ""), item.get("worst", ""), types)) + " |")
        lines.append("")
    else:
        lines += ["未启用或无命中（缺 GITHUB_API_KEY 时声明于采集备注）", ""]

    lines += ["### 搜索引擎 dorking（仅记录结果条目，未抓取目标页面）", ""]
    if data.dork_findings:
        lines += ["| dork | 意图 | 级别 | 命中 | 后端 | 响应状态 | 示例结果 |", "|---|---|---|---|---|---|---|"]
        for r in data.dork_findings[:15]:
            sample = ""
            if r.get("hits"):
                first = r["hits"][0]
                sample = f"{first.get('title', '')} ({first.get('url', '')})"[:120]
            lines.append("| " + " | ".join(_table_cell(v) for v in (
                r.get("dork", ""), r.get("intent", ""), r.get("severity", ""),
                r.get("hit_count", 0), r.get("backend", "—"), r.get("fetch_status", "—"),
                sample)) + " |")
        lines.append("")
    else:
        lines += ["未启用或无产出", ""]
    return lines


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
    filename_suffix: str = "",
) -> dict[str, Path]:
    """保存 Markdown + JSON（始终）与 CSV 资产清单，返回路径表（跨平台 pathlib）。"""
    out_dir = out_dir or get_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() else "_" for c in data.target)
    base = out_dir / f"recon_{safe_target}_{stamp}"

    if filename_suffix:
        base = base.with_name(base.name + "_" + filename_suffix)

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
        for endpoint in data.api_endpoints:
            writer.writerow(['api_endpoint', endpoint.get('path', ''), json.dumps(endpoint, ensure_ascii=False)])
        for route in data.frontend_routes:
            writer.writerow(['frontend_route', route, '静态路由线索（未验证）'])
        for kind, records in (('finding', data.findings), ('coverage', data.coverage),
                              ('workspace_note', data.workspace_notes), ('threat_model', data.threat_models)):
            for item in records:
                writer.writerow([kind, item.get('title') or item.get('surface', ''), json.dumps(item, ensure_ascii=False)])
    return {"markdown": md_path, "json": json_path, "csv": csv_path}
