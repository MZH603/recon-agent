"""填表任务（用户授权扩面）：对存活资产补齐 L1 端口面 + 刷新指纹（增量可续跑）。

权限说明：用户已明确授权对 example.com（授权场景见审计 l1_authorization_context）
扩展 L1 受控端口扫描至全部存活资产。
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from output.report_builder import ReportBuilder
from tools.registry import build_default
from utils.config import get_settings
from utils.logger import audit, err, info, ok, section, warn

TARGET = "example.com"
PRIOR = Path("reports/recon_hubu_edu_cn_20260930_164005.json")
STATE_PATH = Path("reports/fill_progress.json")
PORTS = "80,443,22,8080,8443,3389"
REFRESH_EVERY = 5  # 每扫 5 台落盘一次（可续跑）


def _load_state() -> tuple[ReportBuilder, list[str]]:
    prior = json.loads(PRIOR.read_text(encoding="utf-8"))["report"]
    builder = ReportBuilder(TARGET, scan_level=1, strategy_note="L1 隐蔽主动（全量端口面填补）")
    builder.add_subdomains(prior["subdomains"], prior["alive_hosts"])
    builder.add_tech_cards(prior["tech_cards"])
    if STATE_PATH.exists():
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        for host, ports in state.get("port_map", {}).items():
            builder.data.port_map[host] = ports
        for card in state.get("tech_cards", []):
            builder.add_tech_card(card)
        info(f"续跑：已完成 {len(state.get('done', []))} 台")
    else:
        builder.data.port_map.update(prior.get("port_map", {}))
    todo = [h for h in prior["alive_hosts"] if h not in builder.data.port_map]
    return builder, todo


async def run() -> int:
    settings = get_settings()
    gate = ScanGate(TARGET, batch_mode=True, is_tty=False, requested_level=1)
    registry = build_default(settings, gate, TARGET)
    builder, todo = _load_state()
    audit("l1_fill_start", {"target": TARGET, "todo": len(todo),
                            "note": "用户授权扩面：全部存活资产 L1 端口面填补"})
    section(f"L1 端口面填补：待扫 {len(todo)} 台（限速 3-10s，失败即停）")
    done: list[str] = []
    for index, host in enumerate(todo, 1):
        started = time.monotonic()
        result = await registry.execute(NormalizedToolCall(
            id=f"fill-{host}", name="nmap_scan", arguments={"target": host, "ports": PORTS}))
        elapsed = time.monotonic() - started
        if not result.success:
            err(f"[{index}/{len(todo)}] {host}: {result.error[:100]}")
            builder.add_note(f"端口扫描失败 {host}: {result.error[:120]}")
            done.append(host)
            continue
        builder.add_port_scan(host, result)
        done.append(host)
        fp = await registry.execute(NormalizedToolCall(
            id=f"fp-{host}", name="fingerprint", arguments={"target": host}))
        if fp.success:
            builder.add_tech_card(fp.data)
        info(f"[{index}/{len(todo)}] {host}: {builder.data.port_map.get(host)} "
             f"({elapsed:.0f}s, stopped_early={result.data.get('stopped_early')})")
        if index % REFRESH_EVERY == 0 or index == len(todo):
            state = {"done": done, "port_map": builder.data.port_map,
                     "tech_cards": builder.data.tech_cards}
            STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=1),
                                  encoding="utf-8", newline="")
            ok(f"进度落盘 {index}/{len(todo)}")
    audit("l1_fill_done", {"scanned": len(done)})
    paths = builder.save()
    ok(f"标准报告已更新: {paths['markdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
