"""全级联扫描（L1 基础侦察→L2→L3，v1.1 起 L0 并入 L1）：状态按目标分文件存储，消除跨目标污染。

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
from utils.config import Settings, get_settings
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
        cards = [card for card in state.get("deep_cards", [])
                 if not card.get("error")]
        dir_results = [result for result in state.get("dir_results", [])
                       if result.get("success")]
        return {"deep_cards": cards,
                "dir_results": dir_results,
                "port_map": state.get("port_map", {}),
                "subdomains": state.get("subdomains", []),
                "alive": state.get("alive", []),
                "l3_done": state.get("l3_done", []),
                "dir_deep_results": state.get("dir_deep_results", []),
                "done": {c.get("host") for c in cards}}
    return {"deep_cards": [], "dir_results": [], "port_map": {},
            "subdomains": [], "alive": [], "l3_done": [], "dir_deep_results": [],
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
        "l3_done": state.get("l3_done", []),
        "dir_deep_results": state.get("dir_deep_results", []),
    })
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=1),
                    encoding="utf-8", newline="")


def make_cascade_gate(target: str, level: int, auto_confirm: bool) -> ScanGate:
    """级联门控：level≥2/3 需三次解锁。auto_confirm 为显式参数（非 isatty 推断）。"""
    if auto_confirm and level >= 2:
        # --auto-confirm（仅限授权测试目标自动化验证）按提示内容应答三级门控与逐项确认。
        # 不能用顺序队列：L3 级联里逐项确认（confirm_step）与三级解锁共用同一 prompt_fn，
        # L2 解锁与 L3 解锁之间夹着 stage_l2 的多次逐项确认，顺序队列会把 L3 的解锁码
        # 提前消费为逐项确认答案而被拒。改为按提示语义应答，与弹出顺序无关：
        #   step1 意图 → 回对应级别的 CONFIRM 码；step3 责任声明 → 回固定声明；
        #   逐项确认（"输入 yes 执行"）→ yes；其余兜底 yes。
        # 目标精确串（step2）仍由下方 step2 包装器回填，语义不变。HARD：仅显式 auto-confirm 生效。
        l2_code_3 = "I UNDERSTAND AND AUTHORIZE"

        async def canned(prompt: str) -> str:
            if "CONFIRM 3" in prompt:
                return "CONFIRM 3"
            if "CONFIRM 2" in prompt:
                return "CONFIRM 2"
            if l2_code_3 in prompt:
                return l2_code_3
            return "yes"

        gate = ScanGate(target, batch_mode=False, is_tty=True,
                        prompt_fn=canned, requested_level=1)
        original = gate.request_level_2_step
        original3 = gate.request_level_3_step

        async def step2_wrapper(step: int, plan: str = "") -> tuple[bool, str]:
            if step == 2:
                gate._log_confirm("l2_step2", target)
                return True, target
            return await original(step, plan)

        async def step2_wrapper_l3(step: int, plan: str = "") -> tuple[bool, str]:
            if step == 2:
                gate._log_confirm("l3_step2", target)
                return True, target
            return await original3(step, plan)

        gate.request_level_2_step = step2_wrapper  # type: ignore[method-assign]
        gate.request_level_3_step = step2_wrapper_l3  # type: ignore[method-assign]
        return gate
    return ScanGate(target, batch_mode=False, is_tty=sys.stdin.isatty(), requested_level=level)


async def stage_l0(  # noqa: N802 —— 保留历史名（内容=L1 基础侦察被动段）
    target: str, registry, builder: ReportBuilder, settings
) -> list[str] | None:
    section("Stage L1 · 基础侦察·被动段（拓线/指纹/情报扩容）")
    sub = await registry.execute(NormalizedToolCall(
        id="fs-sub", name="subdomain_enum",
        arguments={"target": target, "recursive": True, "brute": True, "max_hosts": 100}))
    if not sub.success:
        err(f"子域枚举失败: {sub.error[:120]}")
        return None
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
    from collectors.intel_expander import expand_intel

    await expand_intel(builder.data, settings)  # 测绘引擎/组织情报/代码泄漏/dorking（L0）
    ok(f"L1 被动段完成：子域 {len(builder.data.subdomains)} · 存活 {len(alive)}")
    return alive


async def stage_l1(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict) -> int:
    hosts = [target] + [h for h in alive if h != target]
    section(f"Stage L1 · 基础侦察·隐蔽端口段（{len(hosts)} 台存活资产）")

    # 每主机并行，受各自レート限制器控制；整体并发由 MAX_CONCURRENCY / 每主机限速决定
    # 使用信号量限制同时进行的主机数，避免超过总并发上限
    concurrency = getattr(state, '_l1_concurrency', 1)
    sem = asyncio.Semaphore(concurrency)

    async def _scan_one(host: str, index: int) -> None:
        async with sem:
            if host in state["port_map"] and state["port_map"][host] is not None:
                builder.data.port_map[host] = state["port_map"][host]
                info(f"[{index}/{len(hosts)}] {host} 已有端口面（续跑跳过）")
                return
            started = time.monotonic()
            result = await registry.execute(NormalizedToolCall(
                id=f"fs-port-{host}", name="nmap_scan",
                arguments={"target": host, "ports": MAIN_PORTS}))
            elapsed = time.monotonic() - started
            if not result.success:
                err(f"{host}: {result.error[:100]}")
                builder.add_note(f"端口扫描失败 {host}: {result.error[:120]}")
                return
            data = result.data
            attempts = len(data.get("open_ports", [])) + len(data.get("closed", [])) \
                + (1 if data.get("stopped_early") else 0)
            if elapsed < attempts * 3 - 1:
                warn(f"{host}: 限速下界异常（{elapsed:.0f}s < {attempts * 3}s）")
            builder.add_port_scan(host, result)
            state["port_map"][host] = data.get("open_ports", [])
            ok(f"[{index}/{len(hosts)}] {host}: {state['port_map'][host]} ({elapsed:.0f}s)"
               + (" [失败即停]" if data.get("stopped_early") else ""))
            save_state(target, state)

    tasks = [_scan_one(host, i + 1) for i, host in enumerate(hosts)]
    await asyncio.gather(*tasks)
    return 0


async def stage_l2(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict, done_hosts: set[str], gate: ScanGate) -> None:
    section(f"Stage L2 · 深度指纹（待扫 {len([h for h in alive if h not in done_hosts])} 台）")
    for index, host in enumerate(alive, 1):
        if gate.current_level() < 2:
            return
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
        if gate.current_level() < 2:
            return

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
        if gate.current_level() < 2:
            return
        if any(d["target"] == host and d.get("success")
               for d in state["dir_results"]):
            continue
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-dir-{host}", name="dir_enum",
            arguments={"target": host, "paths": SUB_PATHS, "max_paths": len(SUB_PATHS)}))
        state["dir_results"].append({"target": host, "success": result.success,
                                     "data": result.data or {}, "error": result.error[:160]})
        builder.add_dir_enum(host, result)   # result 即 ToolResult（修复 tr_json 未定义回归）
        save_state(target, state)

    if gate.current_level() < 2:
        return
    probe = await registry.execute(NormalizedToolCall(
        id="fs-probe", name="script_probe",
        arguments={"target": target, "code": PROBE_CODE.replace("__TARGET__", target)}))
    if probe.success:
        builder.add_note(f"沙箱探针（安全响应头）: {probe.stdout[:300]}")
        ok(f"沙箱探针完成: {probe.stdout.splitlines()[0] if probe.stdout else 'exit 0'}")
    else:
        err(f"沙箱探针: {probe.error[:120]}")


async def stage_l3(target: str, alive: list[str], registry, builder: ReportBuilder,
                   state: dict, gate: ScanGate) -> None:
    """L3 自适应低扰动（对齐信息搜集全矩阵）：
    dns_enum → alive_os_probe（ICMP 存活+TTL OS）→ service_banner → vhost
    → origin_hunt → reverse_dns（PTR 反查）→ cloud_enum（+子域派生桶名）
    → topology_trace（≤TRACEROUTE_HOST_CAP 台）→ param_mining（高价值 ≤5 台）
    → dir_enum_deep（高价值 ≤5 台）→ api_doc_probe → surface_check（初步脆弱面）。

    HARD：每步前检查门控；tier1（nmap_scan_l3 SYN/UDP/version/OS）不进入级联默认
    执行——留作 agent/操作者逐项确认的显式动作；扰动熔断的主机记入「采样中止清单」，
    绝不硬闯；alive_os_probe 仅限授权范围内主机。
    """
    section("Stage L3 · 自适应低扰动主动侦察（全矩阵）")
    l3_done = state.setdefault("l3_done", [])

    async def _run(tool_id: str, tool_name: str, arguments: dict, key: str) -> dict | None:
        if key in l3_done:
            info(f"[L3] {tool_name} {key} 已完成（续跑跳过）")
            return None
        if gate.current_level() < 3:
            return None
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-l3-{tool_id}", name=tool_name, arguments=arguments))
        l3_done.append(key)
        if result.success:
            builder.add_note(f"L3 {tool_name}: "
                             f"{json.dumps(result.data, ensure_ascii=False, default=str)[:400]}")
            save_state(target, state)
            return result.data
        builder.add_note(f"L3 {tool_name} 失败: {result.error[:160]}")
        return None

    # 1) DNS 枚举（AXFR/泛解析/字典/置换）
    await _run("dns", "dns_enum",
               {"target": target, "try_axfr": True, "permute": True}, f"dns:{target}")

    # 2) 存活探测 + OS 启发式（ICMP ×1 + TTL 判定 + TCP 兜底；仅授权范围内主机）
    probe_hosts = [h for h in dict.fromkeys([target] + alive)
                   if ":" not in h][:50]  # IPv6 无 ICMP ping -4 参数面，收敛 IPv4
    alive_data = await _run("alive", "alive_os_probe",
                            {"target": target, "hosts": probe_hosts}, f"alive:{target}")
    if alive_data and alive_data.get("os_guesses"):
        builder.add_note(
            "L3 OS 启发式: "
            + ", ".join(f"{h}={o}" for h, o in list(alive_data["os_guesses"].items())[:8]))

    # 3) 主机 banner 识别（对 L1 端口面，≤20 端口/台，仅前 5 台）
    port_map = state.get("port_map") or builder.data.port_map
    banner_hosts = [h for h, ports in port_map.items() if ports][:5]
    for host in banner_hosts:
        ports = [p for p in port_map[host] if p in (21, 22, 25, 110, 143, 443, 445, 3306,
                                                    3389, 5432, 5900, 6379, 8080, 9200)][:20]
        if ports:
            await _run(f"banner-{host}", "service_banner",
                       {"target": host, "ports": ports}, f"banner:{host}")

    # 4) vhost / 5) 源站线索（主域各一轮）
    await _run("vhost", "vhost_scan",
               {"target": target, "candidates": sorted(state.get("subdomains", []))[:20]},
               f"vhost:{target}")
    origin_data = await _run("origin", "origin_hunt", {"target": target}, f"origin:{target}")

    # 6) 反向 DNS：被动解析 IP + 源站候选 IP 的 PTR 反查（DoH，零目标接触）
    ptr_ips: list[str] = [ip for ip in (builder.data.ips or []) if ip]
    if origin_data:
        ptr_ips += origin_data.get("current_ips") or []
        ptr_ips += origin_data.get("candidate_origins_record_only") or []
    ptr_ips = list(dict.fromkeys(ptr_ips))
    if ptr_ips:
        await _run("rdns", "reverse_dns",
                   {"target": target, "ips": ptr_ips}, f"rdns:{target}")

    # 7) 云存储（+已发现子域派生桶名候选）
    await _run("cloud", "cloud_enum",
               {"target": target, "subdomains": sorted(state.get("subdomains", []))[:20]},
               f"cloud:{target}")

    # 8) 拓扑追踪（端口面有开放端口的主机，≤TRACEROUTE_HOST_CAP 台）
    trace_hosts = [h for h, ports in port_map.items() if ports][:8]
    for host in trace_hosts:
        await _run(f"trace-{host}", "topology_trace",
                   {"target": host}, f"trace:{host}")

    # 9) 深度目录枚举 + API 文档探测 + 参数挖掘 + 初步脆弱面（高价值主机 ≤5 台）
    interesting = set()
    for card in builder.data.tech_cards:
        h = str(card.get("host", ""))
        tech = card.get("tech") or {}
        if h and not card.get("error") and (
            tech.get("system") or tech.get("middleware") or tech.get("framework")):
            interesting.add(h)
    for host in sorted(interesting)[:5]:
        if gate.current_level() < 3:
            return
        result = await registry.execute(NormalizedToolCall(
            id=f"fs-l3-dir-{host}", name="dir_enum_deep",
            arguments={"target": host, "max_paths": 120}))
        l3_done.append(f"dirdeep:{host}")
        if result.success:
            state.setdefault("dir_deep_results", []).append(
                {"target": host, "success": True, "data": result.data})
            builder.add_note(
                f"L3 dir_enum_deep {host}: 检查 {result.data.get('checked', 0)} 路径，"
                f"发现 {len(result.data.get('found', []))}（High {result.data.get('high_count', 0)}）"
                + ("，[扰动熔断中止]" if result.data.get("suspended") else ""))
        else:
            builder.add_note(f"L3 dir_enum_deep {host} 失败: {result.error[:120]}")
        save_state(target, state)
        await _run(f"docs-{host}", "api_doc_probe", {"target": host}, f"docs:{host}")
        await _run(f"params-{host}", "param_mining", {"target": host}, f"params:{host}")
        await _run(f"surface-{host}", "surface_check", {"target": host}, f"surface:{host}")

    if gate.current_level() < 3:
        return
    ok("L3 完成：扰动台账见各步骤 disturbance 字段；tier1（SYN/UDP/version/OS）未自动执行")


async def run(target: str, authorized: bool, level: int, auto_confirm: bool, note: str,
              settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    if not authorized:
        err("必须 --authorized（HARD）")
        return 2
    gate = make_cascade_gate(target, level, auto_confirm)
    registry = build_default(settings, gate, target)
    try:
        if note:
            audit("cascade_authorization", {"target": target, "level": level, "note": note})
            info(f"授权背景已记录: {note}")
        builder = ReportBuilder(target, scan_level=0,
                                strategy_note=f"级联扫描 L1→L{level}（L0 已并入 L1；高级别自动包含全部低等级）")
        state = load_state(target)
        done_hosts = set(state["done"])
        builder.data.port_map.update(state["port_map"])
        builder.add_tech_cards(state["deep_cards"])

        # v1.1 合并：L0 已并入 L1——被动段与端口段都在 L1 授权下执行
        violations = 0
        if level >= 1 and gate.current_level() >= 1:
            alive = await stage_l0(target, registry, builder, settings)
            if alive is None:
                err("资产枚举未完成；为避免遗漏授权资产，已停止后续 L1/L2/L3。")
                return 2
            state["subdomains"] = builder.data.subdomains
            state["alive"] = alive
            violations = await stage_l1(target, alive, registry, builder, state)
            builder.data.port_map.update(state["port_map"])
        else:
            err("[门控] 级别 0（未解锁）：L0 已并入 L1 基础侦察，请用 --profile stealth/--level 1 及以上")
            return 2
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
                await stage_l2(target, alive, registry, builder, state, done_hosts, gate)
        if level >= 3:
            plan = (f"级联 L3（自适应低扰动·全矩阵）：DNS 枚举/存活+OS/banner/虚拟主机/源站线索/"
                    f"PTR 反查/云存储/拓扑追踪/参数挖掘/深度目录/初步脆弱面（{len(alive)} 台存活）")
            for step in (1, 2, 3):
                granted, text = await gate.request_level_3_step(step, plan=plan)
                if not granted:
                    err(f"L3 门控第 {step}/3 步未通过（{text!r}）→ 以当前级别 L{gate.current_level()} 出报告")
                    level = gate.current_level()
                    break
            else:
                ok(f"L3 已解锁，签名校验: {gate.verify_signature()}")
                await stage_l3(target, alive, registry, builder, state, gate)

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
    finally:
        await registry.aclose()


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
    parser = argparse.ArgumentParser(description="全级联扫描 L1→L2→L3（L0 已并入 L1；高级别自动包含低等级）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--level", type=int, default=2, choices=(0, 1, 2, 3))  # 0=未解锁（L0 已并入 L1）
    parser.add_argument("--auto-confirm", action="store_true")
    parser.add_argument("--note", default="")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.level, args.auto_confirm, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
