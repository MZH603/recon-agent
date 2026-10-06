"""全级联扫描（L0→L1→L2）：请求高级别时自动执行全部低等级扫描（HARD：门控语义不变）。

- Stage L0（自动）：子域枚举 8 源 + DNS/WHOIS/IP + 指纹基线（经由 L1/L2 深度卡合并）+ Wayback/接管
- Stage L1（level≥1）：主站 + 存活子域限速端口扫描（逐台计时 QA）
- Stage L2（level≥2）：三次门控解锁后，全资产深度指纹 + 高价值子域定向路径枚举
- 增量落盘可续跑；深度指纹卡片与 fleet_l2_state.json 兼容互通
"""
from __future__ import annotations

import argparse
import asyncio
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

FLEET_STATE = Path("reports/fleet_l2_state.json")   # 深度指纹卡片库（与 fleet_l2 互通）
MAIN_PORTS = "80,443,22,8080,8443,3389,3306,5432,6379,9929,31337"
SUB_PATHS = ["/admin", "/login", "/api", "/.env", "/.git/HEAD", "/robots.txt",
             "/actuator", "/swagger-ui.html", "/adminer.php", "/wp-login.php",
             "/console", "/docs"]
# 定向枚举目标：从存活列表中选取有指纹识别的主机（动态，不再硬编码）
DIR_TARGETS: list[str] = []
SAVE_EVERY = 3   # 深度指纹每 N 台落盘一次（可续跑）


def load_deep_state() -> dict:
    """加载既有深度指纹卡片库与端口面（与 fleet_l2/fill 互通，避免重复扫描与数据丢失）。"""
    if FLEET_STATE.exists():
        state = json.loads(FLEET_STATE.read_text(encoding="utf-8"))
        cards = state.get("deep_cards", [])
        dir_results = state.get("dir_results", [])
        port_map = state.get("port_map", {})
    else:
        cards, dir_results, port_map = [], [], {}
    return {"deep_cards": cards, "dir_results": dir_results, "port_map": port_map,
            "done": {c.get("host") for c in cards}}


def save_deep_state(cards: list[dict], dir_results: list[dict], port_map: dict,
                    extra: dict | None = None) -> None:
    """增量落盘（HARD：读-改-写合并语义，绝不覆盖其他键——历史上的数据丢失均源于全量覆盖写）。"""
    state: dict = {}
    if FLEET_STATE.exists():
        try:
            state = json.loads(FLEET_STATE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
    state.update({"deep_cards": cards, "dir_results": dir_results, "port_map": port_map})
    if extra:
        state.update(extra)
    FLEET_STATE.write_text(
        json.dumps(state, ensure_ascii=False, indent=1),
        encoding="utf-8", newline="")


def make_cascade_gate(target: str, level: int, auto_confirm: bool) -> ScanGate:
    """级联门控：level≥2 需要走三次解锁；auto_confirm 仅用于授权目标的自动化执行。"""
    if auto_confirm and level >= 2:
        queue = ["CONFIRM 2", "I UNDERSTAND AND AUTHORIZE"]

        async def canned(_prompt: str) -> str:
            return queue.pop(0) if queue else "yes"

        gate = ScanGate(target, batch_mode=False, is_tty=True,
                        prompt_fn=canned, requested_level=1)
        original = gate.request_level_2_step

        async def step2_wrapper(step: int, plan: str = "") -> tuple[bool, str]:
            if step == 2:  # 自动注入目标精确串
                gate._log_confirm("l2_step2", target)
                return True, target
            return await original(step, plan)

        gate.request_level_2_step = step2_wrapper  # type: ignore[method-assign]
        return gate
    return ScanGate(target, batch_mode=False, is_tty=sys.stdin.isatty(), requested_level=level)


async def stage_l0(target: str, registry, builder: ReportBuilder, settings) -> list[str]:
    """被动测绘：子域枚举 + DNS/WHOIS/IP + Wayback/接管候选。"""
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

    assets = await expand_assets(target, settings)
    builder.data.dns = assets["dns"]
    builder.data.ips = assets["ips"]
    builder.data.c_sectors = assets["c_sectors"]
    builder.data.whois = assets["whois"]
    for note in assets["notes"]:
        builder.add_note(note)

    from collectors.enrich import enrich_recon

    await enrich_recon(builder.data, settings)  # Wayback + 接管候选（L0）
    ok(f"L0 完成：子域 {len(builder.data.subdomains)} · 存活 {len(alive)}")
    return alive


async def stage_l1(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict) -> int:
    """隐蔽端口扫描：主站 + 全部存活子域（用户授权扩面），逐台计时验证限速下界。

    HARD：结果逐台写回持久状态（防止中断/事故丢失，未探测清零的关键）。
    """
    hosts = [target] + [h for h in alive if h != target]
    section(f"Stage L1 · 隐蔽端口扫描（全部 {len(hosts)} 台存活资产）")
    violations = 0
    scanned = 0
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
        if elapsed < attempts * 3 - 1:  # HARD：限速下界
            violations += 1
            warn(f"{host}: 限速下界异常（{elapsed:.0f}s < {attempts * 3}s）")
        builder.add_port_scan(host, result)
        state["port_map"][host] = data.get("open_ports", [])
        scanned += 1
        ok(f"[{index}/{len(hosts)}] {host}: {state['port_map'][host]} ({elapsed:.0f}s)"
           + (" [失败即停]" if data.get("stopped_early") else ""))
        if scanned % SAVE_EVERY == 0:
            save_deep_state(state["deep_cards"], state["dir_results"], state["port_map"])
    save_deep_state(state["deep_cards"], state["dir_results"], state["port_map"])
    return violations


async def stage_l2(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict, done_hosts: set[str]) -> None:
    """深度指纹（全资产，跳过已完成）+ 高价值子域定向路径枚举。"""
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
            if index % SAVE_EVERY == 0:
                save_deep_state(state["deep_cards"], state["dir_results"], state["port_map"])
    save_deep_state(state["deep_cards"], state["dir_results"], state["port_map"])

    section("Stage L2 · 高价值子域定向路径枚举")
    # 动态派生：从深度指纹卡片中选取有 system/middleware/server 识别的主机
    interesting = set()
    for card in builder.data.tech_cards:
        h = str(card.get("host", ""))
        tech = card.get("tech") or {}
        if h and not card.get("error") and (
            tech.get("system") or tech.get("middleware") or tech.get("server")
        ):
            interesting.add(h)
    # 保底：如果无指纹命中，至少枚举主站
    if not interesting:
        interesting = {target}
    dir_targets = sorted(interesting)[:10]  # HARD: 上限 10 台
    ok(f"定向枚举目标 {len(dir_targets)} 台: {', '.join(dir_targets[:5])}"
       + (f" +{len(dir_targets)-5}" if len(dir_targets) > 5 else ""))
    for host in dir_targets:
        if any(d["target"] == host for d in state["dir_results"]):
            info(f"{host} 已有枚举结果（跳过）")
            continue
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-dir-{host}", name="dir_enum",
            arguments={"target": host, "paths": SUB_PATHS, "max_paths": len(SUB_PATHS)}))
        state["dir_results"].append({"target": host, "success": result.success,
                                     "data": result.data or {}, "error": result.error[:160]})
        tr_json = state["dir_results"][-1]
        from tools.base import ToolResult

        builder.add_dir_enum(host, ToolResult(name="dir_enum", success=tr_json["success"],
                                              data=tr_json["data"], error=tr_json["error"]))
    save_deep_state(state["deep_cards"], state["dir_results"], state["port_map"])

    # 沙箱探针：主站安全响应头复查（L2）
    probe = await registry.execute(NormalizedToolCall(
        id="fs-probe", name="script_probe",
        arguments={"target": target, "code": PROBE_CODE.replace("__TARGET__", target)}))
    if probe.success:
        builder.add_note(f"沙箱探针（主站安全响应头）: {probe.stdout[:300]}")
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
    state = load_deep_state()
    done_hosts = set(state["done"])
    builder.data.port_map.update(state["port_map"])   # 既有端口面直接进报告（可续跑）
    builder.add_tech_cards(state["deep_cards"])       # 既有深度卡片直接进报告（L1 运行也不丢指纹）

    alive = await stage_l0(target, registry, builder, settings)
    state["subdomains"] = builder.data.subdomains      # L0 结果持久化（防中断丢失）
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

    # 从实际扫描成果填充 metrics（非全零）
    metrics = TaskMetrics()
    metrics.tool_calls = len(builder.data.tech_cards) + len(builder.data.risk_paths) + 1
    metrics.tool_success = len([c for c in builder.data.tech_cards if not c.get("error")])
    metrics.scan_level_reached = gate.current_level()
    metrics.stealth_violations = violations

    # 填充 next_steps / raw_refs（报告第 8/9 节不再为空）
    builder.data.next_steps = _build_next_steps(builder.data, gate.current_level())
    builder.data.raw_refs = [
        "审计日志: %APPDATA%\\recon-agent\\audit.log（哈希链）",
        "深度指纹状态: reports/fleet_l2_state.json",
        "标准报告: reports/recon_<目标>_<时间戳>.md",
    ]

    paths = builder.save(metrics)
    section("级联扫描完成")
    ok(f"级别 L{gate.current_level()} · 标准报告: {paths['markdown']}")
    return 0


def _build_next_steps(data, level: int) -> list[dict]:
    """根据扫描结果生成下一步行动建议（仅在级联路径中使用）。"""
    steps = []
    if data.ips and level == 0:
        steps.append({"command": f"recon-agent -t {data.target} --authorized --profile stealth",
                      "purpose": "L1 隐蔽主动：对主目标限速端口扫描", "risk": "中"})
    if level >= 1:
        open_non_web = [h for h, ports in data.port_map.items()
                        if any(p not in (80, 443) for p in ports)]
        if open_non_web:
            steps.append({"command": f"对 {', '.join(open_non_web[:3])} 做服务版本确认",
                          "purpose": "确认非 web 端口上的服务类型", "risk": "中"})
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="全级联扫描 L0→L1→L2（高级别自动包含低等级）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--level", type=int, default=2, choices=(0, 1, 2))
    parser.add_argument("--auto-confirm", action="store_true",
                        help="L2 自动注入三次确认（仅限授权测试目标）")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.level, args.auto_confirm, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
