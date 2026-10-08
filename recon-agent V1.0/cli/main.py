"""Typer CLI 入口（HARD：授权确认 / 非 TTY 禁 L2 / 保护名单拦截全在代码层）。

三种运行模式：
- 默认流水线：L0 确定性被动采集，无模型依赖；
- --session：LangGraph 持久交互会话（模型不可达暂停，可报告与恢复）；
- --mcp：MCP stdio 服务器，供 Claude/ZCode 等第三方 AI Agent 自主接入。
"""
from __future__ import annotations

import asyncio
import os
import sys

import typer
from rich.console import Console

from utils.config import Settings, get_settings
from utils.logger import err, warn

app = typer.Typer(add_completion=False, help="Recon Agent V1.0 — 授权渗透测试信息搜集（被动优先/三级门控/MCP 接入）")
console = Console()

BANNER = (
    "[bold cyan]recon-agent[/bold cyan] [bold]V1.0[/bold] — 信息搜集 AI Agent\n"
    "[yellow]合规声明：仅用于已获合法授权的安全测试。隐蔽性与目标可用性第一，"
    "默认 L0 受控采集，部分指纹与 SAN 查询会接触远端。[/yellow]"
)

PROFILE_LEVELS = {"passive": 0, "stealth": 1, "aggressive": 2}


def _version_callback(value: bool) -> None:
    """--version：打印版本并退出。"""
    if value:
        console.print("recon-agent V1.0 (0.1.0 → 1.0.0)")
        raise typer.Exit()


def _doctor_callback(value: bool) -> None:
    """--doctor：环境自检并退出（工具/网络/Key/审计链/快照）。"""
    if value:
        from cli.doctor import run_doctor

        raise typer.Exit(run_doctor())


def main() -> None:
    """打包入口（recon-agent = cli.main:main）。"""
    app()


@app.command()
def run(
    target: str = typer.Option(None, "-t", "--target", help="目标：域名/IP/URL/CIDR（MCP 模式可不填）"),
    authorized: bool = typer.Option(False, "--authorized", help="声明已获合法授权（必需）"),
    profile: str = typer.Option("passive", "--profile", help="passive=L0 / stealth=L1 / aggressive=L2"),
    level: int = typer.Option(None, "--level", min=0, max=2, help="扫描深度（2 仍需三级门控+TTY）"),
    model: str = typer.Option(None, "--model", help="任意 LiteLLM 支持的模型名"),
    batch: bool = typer.Option(False, "--batch", help="非交互模式（HARD：永久禁止 L2）"),
    lab: bool = typer.Option(False, "--lab", help="实验环境模式：解锁内网/环回目标（仅限自有/自建环境）"),
    session: bool = typer.Option(False, "--session", help="会话模式（REPL，可逐步升级 L1/L2）"),
    resume: str = typer.Option(None, "--resume", help="恢复已有会话 ID（必须配合 --session）"),
    ui: str = typer.Option('auto', '--ui', help='会话界面: auto|pi|rich'),
    mcp_mode: bool = typer.Option(False, "--mcp", help="MCP stdio 服务器模式（供第三方 Agent 接入）"),
    authorized_for: str = typer.Option(None, "--authorized-for", help="MCP 模式授权范围（逗号分隔域名，HARD 必填）"),
    allow_l1: bool = typer.Option(False, "--allow-l1", help="MCP 模式放行 L1（HARD：L2 在 MCP 下永久禁止）"),
    output_format: str = typer.Option("markdown", "--output-format", "--format", help="markdown|json|csv"),
    max_tokens: int = typer.Option(None, "--max-tokens", help="任务 token 预算"),
    max_cost: float = typer.Option(None, "--max-cost", help="任务成本预算（USD）"),
    output: str = typer.Option(None, "-o", "--output", help="输出文件前缀目录"),
    diff: str = typer.Option(None, "--diff", help="与旧报告 JSON 对比，生成增量差异文件"),
    note: str = typer.Option("", "--note", help="授权背景说明（写入审计日志）"),
    auto_confirm: bool = typer.Option(False, "--auto-confirm",
                                      help="L2 自动注入三次门控确认（仅限授权测试目标/非交互自动化）"),
    doctor: bool = typer.Option(False, "--doctor", callback=_doctor_callback, is_eager=True,
                                help="环境自检（工具/网络/API Key/审计链/快照）"),
    version: bool = typer.Option(None, "--version", callback=_version_callback, is_eager=True,
                                 help="打印版本号"),
) -> None:
    """对授权目标执行信息搜集，或以 MCP 服务器模式供 Agent 接入。"""
    if (resume and not session) or (mcp_mode and (session or resume)):
        err("--resume 必须配合 --session；会话与 --mcp 不兼容")
        raise typer.Exit(2)
    if ui not in ('auto', 'pi', 'rich'):
        err('--ui 必须为 auto|pi|rich')
        raise typer.Exit(2)
    if not mcp_mode:
        console.print(BANNER)
    settings = _settings_with(max_tokens, max_cost)
    if lab:  # HARD: 仅解锁自有实验目标；.gov/.mil 与元数据地址仍绝对拒绝
        settings.LAB_MODE = True
        console.print(
            "[yellow][--lab] 实验环境模式：内网/环回目标已解锁（仅限自有/自建环境）。"
            ".gov/.mil 与 169.254 元数据地址仍绝对拒绝。[/yellow]"
        )
    requested = _resolve_level(profile, level)
    is_tty = sys.stdin.isatty()

    async def _flow() -> int:
        if mcp_mode:
            from server.mcp_server import serve

            roots = [x for x in (authorized_for or "").split(",") if x.strip()]
            return await serve(roots, allow_l1, settings)
        if not target:
            err("缺少目标：请用 -t/--target 指定（MCP 服务器模式请用 --mcp）")
            return 2
        if not authorized:
            granted = await _confirm_authorization(target, batch, is_tty)
            if not granted:
                err("未获授权：仅允许 --authorized 声明后使用；被动模式也已拒绝（HARD）")
                return 2
        from cli import pipeline, session as session_mod

        if session:
            runner = session_mod.run_session
            if is_tty and sys.stdout.isatty() and os.environ.get('TERM') != 'dumb' and not batch and ui != 'rich':
                from cli.pi_bridge import pi_available
                available, reason = pi_available()
                if available:
                    from cli.pi_session import run_pi_session
                    runner = run_pi_session
                elif ui == 'pi':
                    err('Pi 界面不可用: ' + reason)
                    return 2
                else:
                    warn('Pi 依赖未安装，使用 Rich 兼容界面。' + reason)
            return await runner(
                target=target, settings=settings, batch=batch, is_tty=is_tty,
                requested_level=requested, model_override=model,
                output_format=output_format, output_dir=output,
                run_pipeline=pipeline.run_pipeline, resume_id=resume,
            )
        if requested >= 1 and not batch:
            # 级联策略（HARD：门控语义不变）：请求高级别时自动执行全部低等级扫描
            from scripts.full_scan import run as full_cascade

            return await full_cascade(
                target=target, authorized=True, level=requested,
                auto_confirm=auto_confirm or (not is_tty), note=note)
        return await pipeline.run_pipeline(
            target=target, settings=settings, batch=batch, is_tty=is_tty,
            requested_level=requested, model_override=model,
            output_format=output_format, output_dir=output, diff_path=diff,
        )

    raise typer.Exit(asyncio.run(_flow()))


def _settings_with(max_tokens: int | None, max_cost: float | None) -> Settings:
    """CLI 覆盖项注入 Settings（其余阈值固定在 config.py，LLM/参数不可越权）。"""
    settings = get_settings()
    if max_tokens:
        settings.MAX_TOKENS_PER_TASK = max_tokens
    if max_cost:
        settings.MAX_COST_PER_TASK = max_cost
    return settings


def _resolve_level(profile: str, level: int | None) -> int:
    """--profile 与 --level 合一：取两者较大值（aggressive 仍需三级门控解锁）。"""
    by_profile = PROFILE_LEVELS.get(profile, 0)
    if profile not in PROFILE_LEVELS:
        warn(f"未知 profile '{profile}'，按 passive 处理")
    return max(by_profile, level or 0)


async def _confirm_authorization(target: str, batch: bool, is_tty: bool) -> bool:
    """交互授权确认（HARD：batch/无 TTY 且未 --authorized → 拒绝）。"""
    if batch or not is_tty:
        return False
    answer = await asyncio.to_thread(
        input, f"确认你已获得对 {target} 的合法书面授权并将遵守 RoE？(yes/no): "
    )
    return answer.strip().lower() in ("yes", "y", "确认")


if __name__ == "__main__":
    main()
