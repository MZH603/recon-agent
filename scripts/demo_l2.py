"""L2 门控演示：完整走一遍 三次独立确认 → 签名文件 → 逐项确认 → 隐蔽主动采集。

⚠️ 仅限用于已获授权的测试目标（如 scanme.nmap.org、自建靶场、自有资产）。
   对未授权第三方资产使用属于违规行为，与本工具的设计铁律相悖。

用法：
  python -m scripts.demo_l2 --target scanme.nmap.org --authorized
  python -m scripts.demo_l2 --target scanme.nmap.org --authorized --auto-confirm  # 自动化验证/教学演示
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.registry import build_default
from utils.config import get_settings
from utils.logger import audit, err, info, ok, section, warn

DEMO_PORTS = "80,443,22,8080,8443,21,25,3389"
DEMO_PATHS = ["/admin", "/login", "/.env", "/.git/HEAD", "/backup.zip",
              "/robots.txt", "/api", "/phpmyadmin", "/docs", "/server-status",
              "/wp-login.php", "/manager/html", "/actuator", "/adminer.php",
              "/test", "/console", "/index.bak", "/sitemap.xml"]

# 沙箱探针脚本（经 script_probe 工具的 AST+Bandit 三层校验后执行；单次只读请求）
# 沙箱探针脚本（经 script_probe 工具的 AST+Bandit 三层校验后执行；单次只读 GET）
# {target} 占位符由编排脚本注入实际目标
PROBE_CODE = '''"""安全响应头探针：单次 GET 读取安全相关 Header（只读，无利用）。"""
import http.client

conn = http.client.HTTPSConnection("__TARGET__", timeout=10)
conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"})
resp = conn.getresponse()
resp.read(512)
print("status:", resp.status)
for name in ("server", "x-powered-by", "strict-transport-security",
             "content-security-policy", "x-frame-options",
             "x-content-type-options", "set-cookie"):
    print(name + ":", resp.getheader(name))
conn.close()
'''
# 使用时由 scripts/aggressive_l2.py 替换 __TARGET__ 为实际目标


def make_gate(target: str, auto_confirm: bool) -> ScanGate:
    """构造门控：交互模式走真实三次确认；auto-confirm 为演示/测试注入。"""
    if not auto_confirm:
        return ScanGate(target, batch_mode=False, is_tty=sys.stdin.isatty())
    warn("[演示模式] --auto-confirm：由脚本自动注入三次确认与逐项确认（仅限授权测试目标/教学）")

    # 注入序列：step1 意图码 →（step2 由 wrapper 注入目标串）→ step3 责任声明 → 逐项确认 yes
    queue = ["CONFIRM 2", "I UNDERSTAND AND AUTHORIZE"]

    async def canned(_prompt: str) -> str:
        return queue.pop(0) if queue else "yes"

    gate = ScanGate(target, batch_mode=False, is_tty=True, prompt_fn=canned)
    original_step2 = gate.request_level_2_step

    async def step2_wrapper(step: int, plan: str = "") -> tuple[bool, str]:
        if step == 2:  # 注入目标精确串
            gate._log_confirm("l2_step2", target)
            return True, target
        return await original_step2(step, plan)

    gate.request_level_2_step = step2_wrapper  # type: ignore[method-assign]
    return gate


async def run(target: str, authorized: bool, auto_confirm: bool, note: str = "") -> int:
    settings = get_settings()
    if not authorized:
        err("必须 --authorized 声明已获目标授权（HARD）")
        return 2
    gate = make_gate(target, auto_confirm)
    registry = build_default(settings, gate, target)
    if note:
        # 授权背景入审计（HARD：主动操作的授权依据必须留痕）
        audit("l2_authorization_context", {"target": target, "note": note})
        info(f"授权背景已记录: {note}")
    plan = (f"目标 {target}；动作：① 隐蔽端口探测（{DEMO_PORTS}，单线程限速 3-10s）"
            f" ② 有界敏感路径枚举（{len(DEMO_PATHS)} 条，只读 GET）"
            " ③ 沙箱安全响应头探针（单次只读 GET）")
    info("L2 三级门控演示开始")

    # 三次独立确认（HARD：CONFIRM 2 → 目标精确串 → I UNDERSTAND AND AUTHORIZE）
    for step in (1, 2, 3):
        granted, text = await gate.request_level_2_step(step, plan=plan)
        if not granted:
            err(f"门控第 {step}/3 步未通过（输入: {text!r}），已保持/退回 L0")
            return 1
    if not gate.verify_signature():
        err("签名文件校验失败")
        return 1
    ok(f"L2 已解锁，签名校验通过（会话内有效）: {gate.sig_path}")

    results = []
    for name, arguments in (
        ("nmap_scan", {"target": target, "ports": DEMO_PORTS}),
        ("dir_enum", {"target": target, "paths": DEMO_PATHS}),
        ("script_probe", {"target": target, "code": PROBE_CODE}),
    ):
        call = NormalizedToolCall(id=f"demo-{name}", name=name, arguments=arguments)
        result = await registry.execute(call)  # L2 工具在此触发逐项确认（HARD）
        results.append((name, result))
        section(f"{name} 结果")
        if not result.success:
            err(f"{name}: {result.error[:200]}")
            continue
        for ev in result.evidence[:12]:
            ok(ev)
        if result.data.get("stopped_early"):
            warn("[HARD] 检测到连接失败 → 已立即停止主动探测，不重试")
        if result.data.get("found") is not None:
            info(f"发现 {len(result.data['found'])} 项（共检查 {result.data.get('checked')} 条路径）")

    section("演示完成")
    info(f"门控确认记录 {len(gate.confirm_log)} 条（已审计）；隐蔽违规 0；脚本可复查 audit.log")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="L2 三级门控演示（仅限授权测试目标）")
    parser.add_argument("--target", required=True)
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--auto-confirm", action="store_true",
                        help="演示/自动化验证：自动注入三次确认（仅限授权目标）")
    parser.add_argument("--note", default="",
                        help="授权背景说明（写入审计日志，如：课程项目测试，指导教师同意）")
    args = parser.parse_args(argv)
    return asyncio.run(run(args.target, args.authorized, args.auto_confirm, args.note))


if __name__ == "__main__":
    raise SystemExit(main())
