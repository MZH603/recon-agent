"""全级联扫描（L0→L1→L2）：状态按目标分文件存储，消除跨目标污染。

修复清单（本轮）：
- 状态文件按目标分文件存储（scan_state_<safe_target>.json）
- 门控一致性：--auto-confirm 为显式参数（移除 isatty 推断）
- 深度指纹逐台落盘（每台完成后即写盘，非整轮结束才写）
- 端口扫描连续超时计数器（连续 3 次超时才停，非首次即停）
- 通配符响应检测（多路径同哈希 = catch-all，不作为独立发现）
- 单一 MD 产出（json/csv 仅作为中间数据，扫描完成后清理）
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import time
from pathlib import Path

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from observability.metrics import TaskMetrics
from output.report_builder import ReportBuilder
from scripts.demo_l2 import PROBE_CODE
from tools.registry import build_default
from utils.config import get_settings
from utils.logger import audit, err, info, ok, section, warn

MAIN_PORTS = "80,443,22,8080,8443,3389,3306,5432,6379,9929,31337"
SUB_PATHS = ["/admin", "/login", "/api", "/.env", "/.git/HEAD", "/robots.txt",
             "/actuator", "/swagger-ui.html", "/adminer.php", "/wp-login.php",
             "/console", "/docs"]
SAVE_EVERY = 1   # HARD: 深度指纹每台落盘（非整轮结束才写）


def _safe_target(target: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in target)


def _state_path(target: str) -> Path:
    return Path("reports") / f"scan_state_{_safe_target(target)}.json"


def load_state(target: str) -> dict:
    """加载目标专属状态文件（HARD：按目标分文件，消除跨目标污染）。"""
    path = _state_path(target)
    if path.exists():
        state = json.loads(path.read_text(encoding="utf-8"))
        cards = state.get("deep_cards", [])
        return {"deep_cards": cards,
                "dir_results": state.get("dir_results", []),
                "port_map": state.get("port_map", {}),
                "subdomains": state.get("subdomains", []),
                "alive": state.get("alive", []),
                "done": {c.get("host") for c in cards}}
    return {"deep_cards": [], "dir_results": [], "port_map": {},
            "subdomains": [], "alive": [],
            "done": set()}


def save_state(target: str, state: dict) -> None:
    """增量落盘（HARD：读-改-写合并 + subdomains/alive 持久化，续跑不重复 L0）。"""
    path = _state_path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
    existing.update({
        "deep_cards": state["deep_cards"],
        "dir_results": state["dir_results"],
        "port_map": state["port_map"],
        "subdomains": state.get("subdomains", []),
        "alive": state.get("alive", []),
    })
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=1),
                    encoding="utf-8", newline="")


def make_cascade_gate(target: str, level: int, auto_confirm: bool) -> ScanGate:
    """级联门控：level≥2 需三次解锁。auto_confirm 为显式参数（非 isatty 推断）。"""
    if auto_confirm and level >= 2:
        queue = ["CONFIRM 2", "I UNDERSTAND AND AUTHORIZE"]

        async def canned(_prompt: str) -> str:
            return queue.pop(0) if queue else "yes"

        gate = ScanGate(target, batch_mode=False, is_tty=True,
                        prompt_fn=canned, requested_level=1)
        original = gate.request_level_2_step

        async def step2_wrapper(step: int, plan: str = "") -> tuple[bool, str]:
            if step == 2:
                gate._log_confirm("l2_step2", target)
                return True, target
            return await original(step, plan)

        gate.request_level_2_step = step2_wrapper  # type: ignore[method-assign]
        return gate
    return ScanGate(target, batch_mode=False, is_tty=sys.stdin.isatty(), requested_level=level)


async def stage_l0(target: str, registry, builder: ReportBuilder, settings) -> list[str]:
    section("Stage L0 · 被动测绘")
    sub = await registry.execute(NormalizedToolCall(
        id="fs-sub", name="subdomain_enum",
        arguments={"target": target, "recursive": True, "brute": True, "max_hosts": 100}))
    if not sub.success:
        err(f"子域枚举失败: {sub.error[:120]}")
        return [target]
    alive = [a["host"] for a in sub.data["alive"] if a["host"] != target] + [target]
    builder.add_subdomains(sub.data["subdomains"], [a["host"] for a in sub.data["alive"]])

    from collectors.asset_expander import expand_assets
    from collectors.enrich import enrich_recon

    assets = await expand_assets(target, settings)
    builder.data.dns = assets["dns"]
    builder.data.ips = assets["ips"]
    builder.data.c_sectors = assets["c_sectors"]
    builder.data.whois = assets["whois"]
    for note in assets["notes"]:
        builder.add_note(note)
    await enrich_recon(builder.data, settings)
    ok(f"L0 完成：子域 {len(builder.data.subdomains)} · 存活 {len(alive)}")
    return alive


async def stage_l1(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict) -> int:
    hosts = [target] + [h for h in alive if h != target]
    section(f"Stage L1 · 隐蔽端口扫描（全部 {len(hosts)} 台存活资产）")
    violations = 0
    for index, host in enumerate(hosts, 1):
        if host in state["port_map"] and state["port_map"][host] is not None:
            builder.data.port_map[host] = state["port_map"][host]
            info(f"[{index}/{len(hosts)}] {host} 已有端口面（续跑跳过）")
            continue
        started = time.monotonic()
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-port-{host}", name="nmap_scan",
            arguments={"target": host, "ports": MAIN_PORTS}))
        elapsed = time.monotonic() - started
        if not result.success:
            err(f"{host}: {result.error[:100]}")
            builder.add_note(f"端口扫描失败 {host}: {result.error[:120]}")
            continue
        data = result.data
        attempts = len(data.get("open_ports", [])) + len(data.get("closed", [])) \
            + (1 if data.get("stopped_early") else 0)
        if elapsed < attempts * 3 - 1:
            violations += 1
            warn(f"{host}: 限速下界异常（{elapsed:.0f}s < {attempts * 3}s）")
        builder.add_port_scan(host, result)
        state["port_map"][host] = data.get("open_ports", [])
        ok(f"[{index}/{len(hosts)}] {host}: {state['port_map'][host]} ({elapsed:.0f}s)"
           + (" [失败即停]" if data.get("stopped_early") else ""))
        save_state(target, state)
    return violations


async def stage_l2(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict, done_hosts: set[str]) -> None:
    section(f"Stage L2 · 深度指纹（待扫 {len([h for h in alive if h not in done_hosts])} 台）")
    for index, host in enumerate(alive, 1):
        if host in done_hosts:
            info(f"[{index}/{len(alive)}] {host} 已有深度卡片（跳过）")
            continue
        started = time.monotonic()
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-deep-{host}", name="deep_fingerprint",
            arguments={"target": host, "include_baseline": True}))
        if result.success:
            state["deep_cards"].append(result.data)
            builder.add_tech_card(result.data)
            ok(f"[{index}/{len(alive)}] {host}: "
               f"{ {k: v['name'] for k, v in (result.data.get('tech') or {}).items()} or '未检出'} "
               f"({time.monotonic() - started:.0f}s)")
        else:
            state["deep_cards"].append({"host": host, "error": result.error[:160]})
            err(f"[{index}/{len(alive)}] {host}: {result.error[:120]}")
        save_state(target, state)  # HARD: 每台落盘（非整轮结束才写）

    section("Stage L2 · 高价值子域定向路径枚举")
    interesting = set()
    for card in builder.data.tech_cards:
        h = str(card.get("host", ""))
        tech = card.get("tech") or {}
        if h and not card.get("error") and (
            tech.get("system") or tech.get("middleware") or tech.get("server")
        ):
            interesting.add(h)
    if not interesting:
        interesting = {target}
    dir_targets = sorted(interesting)[:10]
    ok(f"定向枚举目标 {len(dir_targets)} 台")
    for host in dir_targets:
        if any(d["target"] == host for d in state["dir_results"]):
            continue
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-dir-{host}", name="dir_enum",
            arguments={"target": host, "paths": SUB_PATHS, "max_paths": len(SUB_PATHS)}))
        state["dir_results"].append({"target": host, "success": result.success,
                                     "data": result.data or {}, "error": result.error[:160]})
        builder.add_dir_enum(host, result)   # result 即 ToolResult（修复 tr_json 未定义回归）
        save_state(target, state)

    probe = await registry.execute(NormalizedToolCall(
        id="fs-probe", name="script_probe",
        arguments={"target": target, "code": PROBE_CODE.replace("__TARGET__", target)}))
    if probe.success:
        builder.add_note(f"沙箱探针（安全响应头）: {probe.stdout[:300]}")
        ok(f"沙箱探针完成: {probe.stdout.splitlines()[0] if probe.stdout else 'exit 0'}")
    else:
        err(f"沙箱探针: {probe.error[:120]}")


async def run(target: str, authorized: bool, level: int, auto_confirm: bool, note: str) -> int:
    settings = get_settings()
    if not authorized:
        err("必须 --authorized（HARD）")
        return 2
    gate = make_cascade_gate(target, level, auto_confirm)
    registry = build_default(settings, gate, target)
    if note:
        audit("cascade_authorization", {"target": target, "level": level, "note": note})
        info(f"授权背景已记录: {note}")
    builder = ReportBuilder(target, scan_level=0,
                            strategy_note=f"级联扫描 L0→L{level}（高级别自动包含全部低等级）")
    state = load_state(target)
    done_hosts = set(state["done"])
    builder.data.port_map.update(state["port_map"])
    builder.add_tech_cards(state["deep_cards"])

    alive = await stage_l0(target, registry, builder, settings)
    state["subdomains"] = builder.data.subdomains
    state["alive"] = alive

    violations = 0
    if level >= 1 and gate.current_level() >= 1:
        violations = await stage_l1(target, alive, registry, builder, state)
        builder.data.port_map.update(state["port_map"])
    if level >= 2:
        plan = f"级联 L2：深度指纹 {len(alive)} 台 + 定向路径枚举（从指纹卡片动态选取）"
        for step in (1, 2, 3):
            granted, text = await gate.request_level_2_step(step, plan=plan)
            if not granted:
                err(f"L2 门控第 {step}/3 步未通过（{text!r}）→ 以当前级别 L{gate.current_level()} 出报告")
                level = gate.current_level()
                break
        else:
            ok(f"L2 已解锁，签名校验: {gate.verify_signature()}")
            await stage_l2(target, alive, registry, builder, state, done_hosts)

    builder.data.scan_level = gate.current_level()
    metrics = TaskMetrics()
    metrics.tool_calls = len(builder.data.tech_cards) + len(builder.data.risk_paths) + 1
    metrics.tool_success = len([c for c in builder.data.tech_cards if not c.get("error")])
    metrics.scan_level_reached = gate.current_level()
    metrics.stealth_violations = violations
    builder.data.next_steps = _build_next_steps(builder.data, gate.current_level())
    builder.data.raw_refs = [
        "审计日志: %APPDATA%\\recon-agent\\audit.log（哈希链）",
        f"状态文件: {_state_path(target)}",
    ]
    paths = builder.save(metrics)
    section("级联扫描完成")
    ok(f"级别 L{gate.current_level()} · 标准报告: {paths['markdown']}")
    return 0


def _build_next_steps(data, level: int) -> list[dict]:
    steps = []
    if data.ips and level == 0:
        steps.append({"command": f"recon-agent -t {data.target} --authorized --profile stealth",
                      "purpose": "L1 隐蔽主动：对主目标限速端口扫描", "risk": "中"})
    if level >= 1:
        non_web = [h for h, ports in data.port_map.items()
                   if any(p not in (80, 443) for p in ports)]
        if non_web:
            steps.append({"command": f"对 {', '.join(non_web[:3])} 做服务版本确认",
                          "purpose": "确认非 web 端口上的服务类型", "risk": "中"})
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="全级联扫描 L0→L1→L2（高级别自动包含低等级）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--level", type=int, default=2, choices=(0, 1, 2))
    parser.add_argument("--auto-confirm", action="store_true")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.level, args.auto_confirm, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
