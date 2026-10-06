"""会话模式（REPL）：LLM 驱动 ReAct（HARD：模型不可达仍降级离线出报告，不崩溃）。"""
from __future__ import annotations

import asyncio

from gate.scan_gate import ScanGate
from model.base import ModelUnavailable
from utils.config import Settings
from utils.logger import info, ok, warn


async def run_session(
    target: str, settings: Settings, batch: bool, is_tty: bool, requested_level: int,
    model_override: str | None, output_format: str, output_dir: str | None,
    run_pipeline,
) -> int:
    """启动会话；模型构建失败或首轮调用失败 → 降级 run_pipeline（离线流水线）。"""
    try:
        from core.llm import LLMService

        llm = LLMService(settings, model_override)
    except Exception as exc:  # noqa: BLE001 —— 配置类错误统一降级
        warn(f"模型不可用（{exc}），降级为离线模板报告")
        return await run_pipeline(target, settings, batch, is_tty, requested_level,
                                  model_override, output_format, output_dir)
    gate = ScanGate(target, batch_mode=batch, is_tty=is_tty, requested_level=requested_level)
    if gate.downgrade_notice:
        warn(gate.downgrade_notice)
    from core.agent import ReconAgent
    from core.prompts import build_system_prompt
    from tools.registry import build_default

    from utils.cache import SQLiteCache
    from platforms.paths import get_cache_dir

    registry = build_default(settings, gate, target)
    cache = SQLiteCache(get_cache_dir() / "semantic_cache.db")
    agent = ReconAgent(target, registry, llm, settings=settings, cache=cache)
    system_prompt = build_system_prompt(registry, gate, llm.model_name, authorized=True)
    info(f"会话模式启动（模型: {llm.model_name}）。命令: 继续/扩面/报告/abort/退出")

    try:
        outcome = await agent.run(
            f"对 {target} 进行系统性信息搜集，按采集清单 ①-⑦ 推进。", system_prompt
        )
    except ModelUnavailable as exc:
        # HARD: 模型不可达 → 降级离线流水线，仍出报告
        warn(f"模型不可达（{exc}），降级为离线模板报告")
        return await run_pipeline(target, settings, batch, is_tty, requested_level,
                                  model_override, output_format, output_dir)
    ok("Agent 一轮执行完成：" + (outcome["answer"][:400] or "(无文本输出)"))
    while True:
        try:
            user = await asyncio.to_thread(input, "recon> ")
        except (EOFError, KeyboardInterrupt):
            break  # stdin 关闭/中断 → 保存并退出
        command = user.strip().lower()
        if command in ("退出", "exit", "quit"):
            break
        if command == "abort":
            gate.abort()
            warn("已退回 L0")
            continue
        if command in ("报告", "生成报告"):
            return _save_session_report(target, agent, gate)
        if not command:
            continue
        try:
            outcome = await agent.run(user.strip(), system_prompt)
        except ModelUnavailable:
            warn("模型不可达，建议直接输入 '报告' 生成离线报告")
            continue
        ok((outcome["answer"][:400]) or "(无文本输出)")
    return _save_session_report(target, agent, gate)


def _save_session_report(target: str, agent, gate: ScanGate) -> int:
    """会话报告落盘：证据一致性校验后保存（HARD：无证据项标 [无证据]）。"""
    from hallucination.consistency import Finding, OutputConsistencyChecker
    from output.report import ReconData, save_report

    data = ReconData(target=target, scan_level=gate.current_level(),
                     strategy_note=f"会话模式（最终 L{gate.current_level()}）")
    known = {src for item in agent.evidence.all() for src in item["evidence"]}
    checker = OutputConsistencyChecker(known)
    report = checker.check(
        [Finding(subject=f"{agent.target}", claim=f"执行工具 {item['tool']}",
                 evidence=item["evidence"], confidence=item["confidence"])
         for item in agent.evidence.all()]
    )
    data.doubts = [f"{f.subject}: {f.claim}" for f in report.flagged]
    paths = save_report(data, agent.metrics, [])
    ok(f"报告已生成: {paths['markdown']}")
    return 0
