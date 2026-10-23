"""System Prompt 加载与占位符替换（HARD：占位符由代码注入，LLM 不可自改授权状态/级别）。"""
from __future__ import annotations

from pathlib import Path

from gate.scan_gate import ScanGate
from tools.registry import ToolRegistry

PROMPT_PATH = Path(__file__).resolve().parent.parent / "system_prompt.txt"

SUPPORTED_MODELS = (
    "OpenAI(gpt-4o/-mini/o1) · Anthropic(claude-3.5-sonnet/opus) · Google(gemini-1.5/2.0) · "
    "Azure OpenAI · 国产兼容端点(DeepSeek/Qwen/GLM/Kimi) · 本地(Ollama/vLLM)"
)


def build_system_prompt(
    registry: ToolRegistry,
    gate: ScanGate,
    current_model: str,
    authorized: bool,
) -> str:
    """读取 system_prompt.txt 并替换全部动态占位符。"""
    template = PROMPT_PATH.read_text(encoding="utf-8")
    stealth = (
        "当前生效的隐蔽参数（不可修改）：\n"
        "- 并发：1（绝对上限 2，超限代码层自动修正）\n"
        "- 请求间隔：L1/L2 随机 3-10 秒\n"
        "- 扫描类型：仅 TCP Connect（禁止 SYN/UDP/NULL/XMAS/FIN）\n"
        "- 探测深度：L1 仅轻量 banner；L2 手段更丰富但禁止无差别爆破\n"
        "- UA：常见浏览器\n"
        "- 失败：立即停止，禁止重试\n"
    )
    replacements = {
        "{AVAILABLE_TOOLS}": "\n".join(f"  - {b}" for b in registry.briefs()) or "  （无）",
        "{STEALTH_POLICY}": stealth,
        "{SUPPORTED_MODELS}": SUPPORTED_MODELS,
        "{CURRENT_MODEL}": current_model,
        "{AUTH_STATUS}": "已授权（--authorized 已声明）" if authorized else "未授权（仅被动记录）",
        "{CURRENT_LEVEL}": f"L{gate.current_level()}",
    }
    result = template
    for key, value in replacements.items():
        result = result.replace(key, value)
    return result + "\n扩展工具采用按需披露：先用 tool_catalog 搜索并 select 工具名，再依据完整 Schema 调用；选择工具不授予 L1/L2 权限。API 静态候选与 mock 请求不得写成已确认接口。\n"


SESSION_PROMPT_PATH = Path(__file__).resolve().parent / "prompt_templates" / "session.md"


def session_prompt(registry, target, settings=None):
    settings = settings or getattr(registry, 'settings', None) or getattr(registry, '_settings', None)
    prompt_file = getattr(settings, 'SESSION_PROMPT_FILE', '')
    if prompt_file:
        main = Path(prompt_file).expanduser().read_text(encoding='utf-8')
    else:
        main = SESSION_PROMPT_PATH.read_text(encoding='utf-8')
    return main + f"\n授权目标：{target}。当前进程按真实门控状态授权，L1 人工确认、L2 解锁和逐动作确认均由代码处理。\n可用工具：" + '; '.join(registry.briefs()) + '\n'
