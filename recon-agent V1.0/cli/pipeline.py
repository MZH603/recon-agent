"""执行流水线：L0 确定性被动采集（无模型也能出报告）（HARD：报告强制水印/降级/一致性校验）。"""
from __future__ import annotations

from pathlib import Path

from gate.scan_gate import ScanGate
from hallucination.consistency import OutputConsistencyChecker
from observability.metrics import TaskMetrics
from output.report import DEGRADED_WATERMARK, ReconData, save_report
from platforms.paths import get_cache_dir
from security.stealth import allowed_target
from utils.cache import SQLiteCache
from utils.config import Settings
from utils.logger import err, info, ok, section, warn


async def run_pipeline(
    target: str, settings: Settings, batch: bool, is_tty: bool, requested_level: int,
    model_override: str | None, output_format: str, output_dir: str | None,
    diff_path: str | None = None,
) -> int:
    """确定性 L0 流水线：拓线 → 指纹 → CVE → 一致性校验 → 报告（无 LLM 依赖）。"""
    ok, reason = allowed_target(target, settings)
    if not ok:
        err(f"[合规拦截] {reason}")
        return 2
    gate = ScanGate(target, batch_mode=batch, is_tty=is_tty, requested_level=requested_level)
    if gate.downgrade_notice:
        warn(gate.downgrade_notice)
    metrics = TaskMetrics(scan_level_reached=gate.current_level())
    data = ReconData(target=target, scan_level=gate.current_level())
    info(f"开始 L0 被动采集: {target}（[🔒] 隐蔽约束全程生效）")

    from collectors.asset_expander import expand_assets
    from collectors.web_fingerprint import collect_tech_cards, extract_product_versions
    from tools.builtin.subdomain_enum import SubdomainEnumTool, SubdomainParams

    assets = await expand_assets(target, settings)

    # 子域名枚举与递归拓线（L0 自主执行）：CT/SAN/前缀验证 + 存活解析 → 精准指纹
    sub_tool = SubdomainEnumTool(settings)
    sub_result = await sub_tool.run(SubdomainParams(target=target))
    if sub_result.success:
        sub_data = sub_result.data
        alive_hosts = [a["host"] for a in sub_data.get("alive", [])]
        # HARD 分离：报告的子域清单 = 全量（≤100）；指纹队列单独截断（礼貌上限 12）
        all_hosts = sorted(set(assets["subdomains"]) | set(sub_data["subdomains"]))[:100]
        fp_queue = sorted(set(alive_hosts) & set(all_hosts)) + sorted(
            set(all_hosts) - set(alive_hosts)
        )
        assets["subdomains"] = all_hosts
        data.fp_queue = [target] + [h for h in fp_queue if h != target]
        data.alive_hosts = sorted(set(alive_hosts) | {target})
        assets["notes"].append(
            f"子域枚举(subdomain_enum): 发现 {len(sub_data['subdomains'])} 个"
            f"（源分布 {sub_data['sources']}），存活 {len(alive_hosts)} 个"
        )
        if sub_data.get("san"):
            assets["notes"].append(f"TLS SAN 线索: {', '.join(sub_data['san'][:6])}")
    else:
        assets["notes"].append(f"子域枚举失败（不重试）: {sub_result.error[:120]}")

    data.dns = assets["dns"]
    data.subdomains = assets["subdomains"]
    data.out_of_scope = assets["out_of_scope"]
    data.whois = assets["whois"]
    data.ips = assets["ips"]
    data.c_sectors = assets["c_sectors"]
    data.notes = assets["notes"]

    data.tech_cards = await collect_tech_cards(data.fp_queue, settings)
    for card in data.tech_cards:  # 端口列：由探测成功的 scheme 推断（L1 扫描后回填真实端口）
        host, scheme = str(card.get("host", "")), card.get("scheme", "")
        if not card.get("error") and host and scheme:
            data.port_map[host] = [443] if scheme == "https" else [80]
    data.degraded = _collect_degraded(data)
    data.cves = await _lookup_cves(extract_product_versions(data.tech_cards), settings)
    data.doubts = _collect_doubts(data)
    data.next_steps = _build_next_steps(data)

    from collectors.enrich import enrich_recon

    await enrich_recon(data, settings)  # Wayback 历史端点 + 子域接管候选（L0）
    metrics.incr("tool_calls", len(data.tech_cards))
    metrics.incr("tool_success", sum(1 for c in data.tech_cards if not c.get("error")))
    metrics.incr("cve_unknown_count", sum(1 for c in data.cves if c.get("status") in ("未收录", "不可用")))

    data.raw_refs = ["JSON 同名文件（完整结构化数据）", "utils/config.py::Settings（全部阈值）"]
    if output_format == "json":
        info("输出格式 json：报告仍同时保存 Markdown + JSON（HARD）")
    watermarks = []
    if data.degraded:
        watermarks.append(DEGRADED_WATERMARK)  # HARD: 降级水印
    if diff_path:
        return _finalize(data, metrics, watermarks, output_dir, diff_path)
    return _finalize(data, metrics, watermarks, output_dir)


def _write_diff(data, diff_path: Path, markdown_path: Path) -> None:
    """生成增量对比文件（P0-1）；旧报告读取失败显式告警。"""
    import json

    from output.diff import diff_reports

    try:
        old = json.loads(Path(diff_path).read_text(encoding="utf-8"))["report"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        err(f"diff 旧报告读取失败: {exc}")
        return
    diff_md = diff_reports(old, data)
    out = markdown_path.parent / f"{markdown_path.stem}_diff.md"
    out.write_text(diff_md, encoding="utf-8", newline="")
    ok(f"增量对比: {out}")


def _collect_degraded(data: ReconData) -> list[str]:
    """从指纹失败/备注中提取降级清单（HARD：报告必须标注）。"""
    degraded: list[str] = []
    for card in data.tech_cards:
        if card.get("error"):
            degraded.append(f"指纹探测失败 {card['host']}（置信度下调，未推测填补）")
    degraded += [n[:160] for n in data.notes if ("降级" in n or "不可达" in n or "失败" in n)]
    return degraded


async def _lookup_cves(product_versions: list[tuple[str, str]], settings: Settings) -> list[dict]:
    """按确认的产品版本查签名快照（HARD：未收录硬输出，不编造编号）。"""
    from knowledge.cve_base import CVEKnowledgeBase
    from platforms.paths import get_cve_dir

    kb, load_note = CVEKnowledgeBase.load(
        get_cve_dir() / "snapshot.json", get_cve_dir() / "snapshot.sig"
    )
    if kb is None:
        return [{"product": "CVE知识库", "status": "不可用", "note": load_note}]
    return [kb.lookup(product, version) for product, version in product_versions]


def _collect_doubts(data: ReconData) -> list[str]:
    """存疑清单：指纹多源冲突 + 探测失败 + 未收录 CVE（HARD：不二选一、不推测）。"""
    doubts: list[str] = []
    for card in data.tech_cards:
        for category, item in (card.get("tech") or {}).items():
            for alt in item.get("alternatives", []):
                doubts.append(f"{card['host']} {category}: {item['name']} vs {alt['name']}"
                              " [冲突，需人工核实]")
        if card.get("error"):
            doubts.append(f"{card['host']}: 探测失败 [未确认，建议人工核实]")
    doubts += [
        f"CVE {cve.get('product')}: {cve.get('status')}（快照否定/缺失，不编造编号）"
        for cve in data.cves if cve.get("status") in ("未收录", "不可用")
    ]
    return doubts


def _build_next_steps(data: ReconData) -> list[dict]:
    """建议命令 + 目的 + 风险（HARD：L2 项标 ⚠️ 注明需三级确认）。"""
    steps: list[dict] = []
    if data.ips and data.scan_level == 0:
        steps.append({"command": f"recon-agent -t {data.target} --authorized --profile stealth",
                      "purpose": "L1 隐蔽主动：对主目标限速 TCP Connect 探测常见端口",
                      "risk": "中", "needs_gate": False})
    if data.c_sectors:
        steps.append({"command": "nmap -sT --max-rate 1 --max-parallelism 1 -p 80,443 <授权IP>",
                      "purpose": "对已确认授权的 C 段主机做隐蔽端口确认（仅限授权范围）",
                      "risk": "中", "needs_gate": False})
    if data.subdomains:
        steps.append({"command": "对高价值子域执行目录枚举/版本识别",
                      "purpose": "L2 深入探测（目录枚举、脚本探测）",
                      "risk": "高", "needs_gate": True})
    return steps


def _finalize(data: ReconData, metrics: TaskMetrics, watermarks: list[str],
              output_dir: str | None, diff_path: str | None = None) -> int:
    """一致性校验（CI 可阻断）→ 保存 → 汇总输出。"""
    known: set[str] = set()
    for card in data.tech_cards:
        for item in (card.get("tech") or {}).values():
            known.add(item.get("source", ""))
    checker = OutputConsistencyChecker({s for s in known if s})
    from hallucination.consistency import Finding

    findings = [
        Finding(subject=card.get("host", ""), claim=f"{k}={v['name']}",
                evidence=[v.get("source", "")], confidence=v.get("confidence", 0.5))
        for card in data.tech_cards for k, v in (card.get("tech") or {}).items()
    ]
    consistency = checker.check(findings)
    if consistency.flagged:
        data.doubts += [f"{f.subject}: {f.claim}" for f in consistency.flagged]
    # HARD: [INCOMPLETE] 水印仅在真实预算耗尽（LLM 会话路径）时置顶；纯流水线无 LLM 消耗
    out = Path(output_dir) if output_dir else None
    paths = save_report(data, metrics, watermarks, out)
    if diff_path:
        _write_diff(data, Path(diff_path), paths["markdown"])
    section("采集完成")
    ok(f"报告: {paths['markdown']}")
    ok(f"JSON: {paths['json']} · CSV: {paths['csv']}")
    info(f"语义缓存: {get_cache_dir()}")
    info(metrics.summary())
    return 0
