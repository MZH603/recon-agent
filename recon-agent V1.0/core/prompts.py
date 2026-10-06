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
    return result
