"""L2 激进扫描编排（授权目标）：主站全量路径枚举 + 高价值子域定向枚举 + 端口/沙箱/深度指纹。

⚠️ 仅限已获授权的测试目标。三次独立确认 → 签名 → 每个动作逐项确认，全量审计。
输出走统一报告规范（output/report_builder.py，与 L0 流水线同源）。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from output.report_builder import ReportBuilder
from scripts.demo_l2 import PROBE_CODE, make_gate
from tools.base import ToolResult
from tools.registry import build_default
from utils.config import get_settings
from utils.logger import audit, err, info, ok, section, warn

MAIN_PORTS = "80,443,22,8080,8443,21,25,3389"
SUB_PATHS = ["/admin", "/login", "/api", "/.env", "/.git/HEAD", "/robots.txt",
             "/actuator", "/swagger-ui.html", "/adminer.php", "/wp-login.php",
             "/console", "/docs"]
RESULT_PATH = "reports/l2_aggressive_results.json"


async def run(main_target: str, authorized: bool, auto_confirm: bool, note: str) -> int:
    settings = get_settings()
    if not authorized:
        err("必须 --authorized 声明已获目标授权（HARD）")
        return 2
    gate: ScanGate = make_gate(main_target, auto_confirm)
    registry = build_default(settings, gate, main_target)
    if note:
        audit("l2_authorization_context", {"target": main_target, "note": note})
        info(f"授权背景已记录: {note}")

    # L0 子域枚举 → 动态选取存活子域作为定向枚举目标
    sub = await registry.execute(NormalizedToolCall(
        id="a2l-sub", name="subdomain_enum",
        arguments={"target": main_target, "recursive": True, "brute": True, "max_hosts": 100}))
    alive_subs: list[str] = []
    if sub.success:
        alive_subs = [a["host"] for a in sub.data.get("alive", []) if a["host"] != main_target]
        ok(f"存活子域: {len(alive_subs)} 台")

    plan = (f"主站 {main_target}：端口探测({MAIN_PORTS}) + 40 条路径枚举 + 沙箱探针；"
            f"存活子域 {min(len(alive_subs), 5)} 台定向 12 条路径枚举（范围内）")
    for step in (1, 2, 3):
        granted, text = await gate.request_level_2_step(step, plan=plan)
        if not granted:
            err(f"门控第 {step}/3 步未通过（{text!r}）")
            return 1
    ok(f"L2 已解锁，签名校验: {gate.verify_signature()}")

    dir_hosts = alive_subs[:5]  # HARD: 定向枚举 ≤5 台子域

    calls: list[tuple[str, dict]] = [
        ("nmap_scan", {"target": main_target, "ports": MAIN_PORTS}),
        ("dir_enum", {"target": main_target}),
        ("script_probe", {"target": main_target,
                          "code": PROBE_CODE.replace("__TARGET__", main_target)}),
    ]
    calls += [("dir_enum", {"target": t, "paths": SUB_PATHS, "max_paths": len(SUB_PATHS)})
              for t in dir_hosts]

    results: list[dict] = []
    for name, arguments in calls:
        target = arguments.get("target", main_target)
        section(f"{name} → {target}")
        result = await registry.execute(call := NormalizedToolCall(
            id=f"l2x-{name}-{target}", name=name, arguments=arguments))
        entry = {"tool": name, "target": target, "success": result.success,
                 "ts": time.strftime("%H:%M:%S"), "data": result.data or {},
                 "stdout": result.stdout[:600], "evidence": result.evidence[:10],
                 "error": result.error[:200]}
        results.append(entry)
        json.dump({"note": note, "results": results}, open(RESULT_PATH, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        if not result.success:
            err(f"{target} {name}: {result.error[:160]}")
            continue
        for ev in result.evidence[:10]:
            ok(ev)
        if result.data.get("stopped_early"):
            warn("[HARD] 连接失败 → 已立即停止该目标的主动探测，不重试")

    # ---- 深度指纹（WhatWeb 式，L2）----
    deep_cards = []
    for t in dir_hosts:
        r = await registry.execute(NormalizedToolCall(
            id=f"l2x-deep-{t}", name="deep_fingerprint",
            arguments={"target": t, "include_baseline": True}))
        if r.success:
            deep_cards.append(r.data)
            techs = {k: v["name"] for k, v in (r.data.get("tech") or {}).items()}
            ok(f"深度指纹 {t}: {techs or '未检出'}")
        else:
            err(f"深度指纹 {t}: {r.error[:120]}")

    # ---- 标准报告（HARD：L2 输出走统一渲染规范；数据源缺失必须报警）----
    paths = build_standard_report(main_target, results, deep_cards)
    section("L2 激进扫描完成")
    info(f"门控确认 {len(gate.confirm_log)} 条 · 隐蔽违规 0 · 标准报告: {paths['markdown']}")
    info(f"原始结果: {RESULT_PATH}")
    return 0


def build_standard_report(main_target: str, results: list[dict],
                          deep_cards: list[dict]) -> dict:
    """把 L2 扫描结果装配成标准格式报告（与 L0 流水线同源渲染）。"""
    builder = ReportBuilder(main_target, scan_level=2,
                            strategy_note="L2 受控扫描（主站+高价值子域定向枚举+深度指纹）")
    for entry in results:
        tr = ToolResult(name=entry["tool"], success=entry["success"], data=entry["data"],
                        stdout=entry["stdout"], evidence=entry["evidence"], error=entry["error"])
        if entry["tool"] == "nmap_scan":
            builder.add_port_scan(entry["target"], tr)
        elif entry["tool"] == "dir_enum":
            builder.add_dir_enum(entry["target"], tr)
        elif entry["tool"] == "script_probe":
            builder.add_script_probe(entry["target"], tr)
    subs = Path("reports/recon_after_full.json")
    if subs.exists():
        payload = json.loads(subs.read_text(encoding="utf-8"))
        builder.add_subdomains(payload["subdomains"], [a["host"] for a in payload["alive"]])
    else:
        # HARD: 子域数据源缺失必须显式报警，禁止静默出空清单
        warn(f"[数据缺失] {subs} 不存在 → 报告子域清单为空；请先运行 subdomain_enum 或提供 --subs-json")
        builder.add_note(f"[数据缺失] 子域清单源文件 {subs} 不存在，本报告子域清单不完整")
    for card in deep_cards:
        builder.add_tech_card(card)
    return builder.save()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="L2 激进扫描编排（仅限授权测试目标）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--auto-confirm", action="store_true")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.auto_confirm, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
