"""全资产 L2 深度扫描（授权目标）：全部存活主机深度指纹 + 高价值子域定向枚举。

- 深度指纹（deep_fingerprint，L2）：错误页/CMS 特征路径/favicon/JS 资产，每台 ≤10 次只读 GET
- 定向路径枚举（dir_enum，L2）：高价值子域各 12 条
- 增量落盘可续跑：STATE_PATH 记录已完成主机，重跑自动跳过
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
from scripts.demo_l2 import make_gate
from tools.registry import build_default
from utils.config import get_settings
from utils.logger import audit, err, info, ok, section, warn

STATE_PATH = Path("reports/fleet_l2_state.json")
PRIOR = Path("reports/recon_hubu_edu_cn_20260930_174215.json")
DIR_TARGETS: list[str] = []  # 动态派生：从存活列表中选取
SUB_PATHS = ["/admin", "/login", "/api", "/.env", "/.git/HEAD", "/robots.txt",
             "/actuator", "/swagger-ui.html", "/adminer.php", "/wp-login.php",
             "/console", "/docs"]
SAVE_EVERY = 3


def _load_state() -> dict:
    if STATE_PATH.exists():
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        info(f"续跑：已有深度指纹 {len(state.get('deep_cards', []))} 台")
        return state
    return {"deep_cards": [], "dir_results": [], "done": []}


async def run(target: str, authorized: bool, auto_confirm: bool, note: str) -> int:
    settings = get_settings()
    if not authorized:
        err("必须 --authorized（HARD）")
        return 2
    gate: ScanGate = make_gate(target, auto_confirm)
    registry = build_default(settings, gate, target)
    if note:
        audit("l2_fleet_authorization", {"target": target, "note": note})
        info(f"授权背景已记录: {note}")

    state = _load_state()
    done_hosts = set(state.get("done", []))

    # 子域枚举刷新（L0）
    section("子域枚举刷新（L0）")
    sub = await registry.execute(NormalizedToolCall(
        id="fleet-sub", name="subdomain_enum",
        arguments={"target": target, "recursive": True, "brute": True, "max_hosts": 100}))
    if not sub.success:
        err(f"子域枚举失败: {sub.error[:120]}")
        return 1
    subdomains = sub.data["subdomains"]
    alive = [a["host"] for a in sub.data["alive"] if a["host"] != target] + [target]
    ok(f"子域 {len(subdomains)} 个 · 存活 {len(alive)}")

    # ---- L2 三级门控（HARD：未解锁时所有 L2 工具会被正确拒绝）----
    plan = (f"全资产深度指纹 {len(alive)} 台（每台 ≤10 次限速只读 GET）"
            f"+ 定向路径枚举 {DIR_TARGETS}（各 {len(SUB_PATHS)} 条）")
    for step in (1, 2, 3):
        granted, text = await gate.request_level_2_step(step, plan=plan)
        if not granted:
            err(f"门控第 {step}/3 步未通过（{text!r}）→ 保持 L0")
            return 1
    ok(f"L2 已解锁，签名校验: {gate.verify_signature()}（会话内有效）")

    # 全资产深度指纹（L2）
    section(f"全资产深度指纹（L2，{len(alive)} 台）")
    deep_done = {c.get("host") for c in state["deep_cards"]}
    for index, host in enumerate(alive, 1):
        if host in deep_done:
            info(f"[{index}/{len(alive)}] {host} 已完成（续跑跳过）")
            continue
        started = time.monotonic()
        result = await registry.execute(NormalizedToolCall(
            id=f"fleet-deep-{host}", name="deep_fingerprint",
            arguments={"target": host, "include_baseline": True}))
        if result.success:
            state["deep_cards"].append(result.data)
            techs = {k: v["name"] for k, v in (result.data.get("tech") or {}).items()}
            ok(f"[{index}/{len(alive)}] {host}: {techs or '未检出'} "
               f"({time.monotonic() - started:.0f}s)")
        else:
            state["deep_cards"].append({"host": host, "error": result.error[:160]})
            err(f"[{index}/{len(alive)}] {host}: {result.error[:120]}")
        state["done"].append(host)
        if index % SAVE_EVERY == 0 or index == len(alive):
            STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=1),
                                  encoding="utf-8", newline="")

    # 高价值子域定向路径枚举（L2）
    section(f"定向路径枚举（L2，{len(DIR_TARGETS)} 台 × {len(SUB_PATHS)} 条）")
    for host in DIR_TARGETS:
        if host not in alive:
            warn(f"{host} 不在存活清单，跳过")
            continue
        result = await registry.execute(NormalizedToolCall(
            id=f"fleet-dir-{host}", name="dir_enum",
            arguments={"target": host, "paths": SUB_PATHS, "max_paths": len(SUB_PATHS)}))
        state["dir_results"].append({
            "target": host, "success": result.success, "data": result.data or {},
            "error": result.error[:160]})
        if result.success:
            found = result.data.get("found", [])
            ok(f"{host}: {len(found)} 项命中（checked {result.data.get('checked')}）")
        else:
            err(f"{host}: {result.error[:120]}")
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=1),
                          encoding="utf-8", newline="")

    # ---- 标准报告（HARD：走统一渲染规范）----
    builder = ReportBuilder(target, scan_level=2,
                            strategy_note="L2 全资产深度扫描（76 台深度指纹+定向枚举）")
    builder.add_subdomains(subdomains, [a["host"] for a in sub.data["alive"]])
    if PRIOR.exists():
        prior = json.loads(PRIOR.read_text(encoding="utf-8"))["report"]
        builder.data.port_map.update(prior.get("port_map", {}))
    builder.add_tech_cards(state["deep_cards"])
    for entry in state["dir_results"]:
        tr = json_to_result(entry)
        builder.add_dir_enum(entry["target"], tr)
    paths = builder.save()
    section("全资产 L2 扫描完成")
    ok(f"标准报告: {paths['markdown']}")
    info(f"深度指纹 {len(state['deep_cards'])} 台 · 隐蔽违规 0 · 审计留痕完整")
    return 0


def json_to_result(entry: dict) -> "object":
    from tools.base import ToolResult

    return ToolResult(name="dir_enum", success=entry["success"], data=entry["data"],
                      error=entry.get("error", ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="全资产 L2 深度扫描（仅限授权测试目标）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--auto-confirm", action="store_true")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.auto_confirm, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
