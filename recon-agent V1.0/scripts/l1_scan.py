"""L1 扫描 + 全程功能 QA（授权目标）。

流程：QA1 门控拒绝检查（L0 下 L1 工具必须被拒）→ L1 显式确认 → 子域枚举 →
主站+存活子域限速端口扫描（逐台计时验证限速下界）→ 标准报告生成 → QA 清单输出。

QA 检查项（对应设计要求）：
1. L0 下 L1 工具被门控拒绝（HARD）
2. batch 下 requested_level=1 显式声明即一次确认（设计语义）
3. 端口扫描成功且耗时 ≥ 尝试次数×3s（限速下界）
4. 失败即停生效（stopped_early 可观察）
5. 范围合规：全部扫描目标属于主域或其子域
6. 审计哈希链完整
7. 标准报告章节齐全 + 端口列真实回填
8. 隐蔽违规计数 = 0
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from observability.metrics import TaskMetrics
from output.report_builder import ReportBuilder
from security.stealth import is_in_scope
from tools.registry import build_default
from utils.config import get_settings
from utils.logger import audit, err, info, ok, section, verify_audit_chain, warn

MAIN_PORTS = "80,443,22,8080,8443,3389"
SUB_HOST_LIMIT = 10   # HARD: L1 端口扫描的子域数量上限（礼貌节奏）
RESULT_PATH = "reports/l1_scan_results.json"

QA: list[dict] = []


def qa(name: str, passed: bool, detail: str = "") -> None:
    QA.append({"check": name, "passed": passed, "detail": detail})
    (ok if passed else err)(f"[QA] {'✅' if passed else '❌'} {name}" + (f" — {detail}" if detail else ""))


async def run(target: str, authorized: bool, note: str) -> int:
    settings = get_settings()
    if not authorized:
        err("必须 --authorized（HARD）")
        return 2
    metrics = TaskMetrics()
    if note:
        audit("l1_authorization_context", {"target": target, "note": note})

    # ---- QA1：L0 下 L1 工具必须被门控拒绝（HARD）----
    gate0 = ScanGate(target, batch_mode=True, is_tty=False)
    reg0 = build_default(settings, gate0, target)
    r0 = await reg0.execute(NormalizedToolCall(
        id="qa-gate", name="nmap_scan", arguments={"target": target, "ports": "80,443"}))
    qa("L0 下 L1 工具被门控拒绝", (not r0.success) and "[门控]" in r0.error, r0.error[:80])

    # ---- L1 会话（batch 下显式 requested_level=1 = 一次性确认，审计留痕）----
    gate = ScanGate(target, batch_mode=True, is_tty=False, requested_level=1)
    qa("L1 显式声明生效", gate.current_level() == 1,
       "batch 下 requested_level=1 即一次确认（HARD：L2 仍永久禁止）")
    if note:
        audit("l1_scan_start", {"target": target, "note": note, "level": gate.current_level()})
    registry = build_default(settings, gate, target)
    builder = ReportBuilder(target, scan_level=1, strategy_note="L1 隐蔽主动（子域枚举+限速端口扫描）")

    # ---- 子域枚举（L0 自动）----
    section("子域枚举（L0）")
    sub = await registry.execute(NormalizedToolCall(
        id="s1", name="subdomain_enum",
        arguments={"target": target, "recursive": True, "brute": True, "max_hosts": 100}))
    if not sub.success:
        err(f"子域枚举失败: {sub.error[:120]}")
        return 1
    alive = [a["host"] for a in sub.data["alive"] if a["host"] != target]
    builder.add_subdomains(sub.data["subdomains"], [a["host"] for a in sub.data["alive"]])
    qa("子域枚举多源命中", len(sub.data["subdomains"]) >= 20,
       f"{len(sub.data['subdomains'])} 个（源 {sub.data['sources']}），存活 {len(alive)}")

    # ---- L1 端口扫描：主站 + 存活子域（有界）----
    section(f"L1 端口扫描（{target} + 存活子域 ×{min(SUB_HOST_LIMIT, len(alive))}）")
    hosts = [target] + alive[:SUB_HOST_LIMIT]
    scanned, violations = 0, 0
    for host in hosts:
        started = time.monotonic()
        result = await registry.execute(NormalizedToolCall(
            id=f"p-{host}", name="nmap_scan",
            arguments={"target": host, "ports": MAIN_PORTS}))
        elapsed = time.monotonic() - started
        if not result.success:
            err(f"{host} 端口扫描失败: {result.error[:100]}")
            continue
        data = result.data
        attempts = len(data.get("open_ports", [])) + len(data.get("closed", [])) \
            + (1 if data.get("stopped_early") else 0)
        # QA：限速下界——每次尝试前有 3-10s 随机延迟（HARD），耗时不得低于 次数×3s
        rate_ok = elapsed >= attempts * 3 - 1
        if not rate_ok:
            violations += 1
        qa(f"限速合规 {host}", rate_ok,
           f"尝试 {attempts} 次，耗时 {elapsed:.1f}s（下界 {attempts * 3:.0f}s）")
        if data.get("stopped_early"):
            ok(f"{host}: 失败即停生效（HARD）")
        builder.add_port_scan(host, result)
        scanned += 1
    qa("范围合规（全部目标在授权范围内）",
       all(is_in_scope(h, target) for h in hosts), f"{len(hosts)} 台")
    qa("隐蔽违规计数 = 0", violations == 0, f"限速检查违例 {violations}")

    # ---- 指纹卡片（复用最新采集数据，保证总表丰富度）----
    prior = Path("reports/recon_hubu_edu_cn_20260930_151154.json")
    if prior.exists():
        builder.add_tech_cards(json.loads(prior.read_text(encoding="utf-8"))["report"]["tech_cards"])
        builder.add_note("指纹卡片复用 151154 轮数据（本轮增量项为端口面）")

    # ---- 审计链与报告 ----
    chain_ok, chain_n, chain_msg = verify_audit_chain()
    qa("审计哈希链完整", chain_ok, f"{chain_n} 条 · {chain_msg}")
    metrics.stealth_violations = violations
    paths = builder.save(metrics)
    md = paths["markdown"].read_text(encoding="utf-8")
    qa("标准报告章节齐全", all(s in md for s in
       ("子域名清单", "存活资产总表", "技术栈明细", "关联资产拓线图", "存疑清单")))
    qa("端口列真实回填", any("| 443" in line or "| 80," in line
       for line in md.splitlines() if line.startswith("|")), "存活资产总表端口列")

    section("QA 清单结果")
    passed = sum(1 for q in QA if q["passed"])
    info(f"QA 通过 {passed}/{len(QA)} · 扫描主机 {scanned} 台")
    json.dump({"qa": QA, "hosts": hosts, "metrics": metrics.model_dump()},
              open(RESULT_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    info(f"QA 结果: {RESULT_PATH} · 标准报告: {paths['markdown']}")
    return 0 if passed == len(QA) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="L1 扫描 + 全程功能 QA（仅限授权测试目标）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
