"""结构化上下文裁剪器（HARD：优先级 不裁剪 > 摘要 > 落盘指针 > 丢弃；保留稳定前缀供 Prompt Cache）。"""
from __future__ import annotations


def estimate_tokens(text: str) -> int:
    """轻量 token 粗估（len/4）：预算控制精度足够，避免额外依赖。"""
    return max(1, len(text or "") // 4)


class ContextTrimmer:
    """在保证 LLM 能继续决策的前提下最大化裁剪已注入上下文。

    策略：
    1. 保留 system（首条）——稳定前缀，供 Prompt Cache 命中；
    2. 最近 keep_recent 条消息完整保留（Raw 层）；
    3. 更早的长内容 → 截断为指针（Compaction 层，原始输出已落盘可恢复）。
    """

    def __init__(self, budget: int, keep_recent: int = 4) -> None:
        self._budget = budget
        self._keep_recent = keep_recent

    def trim(self, messages: list[dict], budget: int | None = None) -> tuple[list[dict], int]:
        """返回 (裁剪后消息, 节省的 token 数)。"""
        limit = budget or self._budget
        total = sum(estimate_tokens(str(m.get("content") or "")) for m in messages)
        if total <= limit:
            return messages, 0
        keep = min(self._keep_recent, max(0, len(messages) - 1))
        head, middle, tail = messages[:1], messages[1:len(messages) - keep], messages[len(messages) - keep:]
        out: list[dict] = list(head)
        saved = 0
        for msg in middle:
            content = str(msg.get("content") or "")
            tokens = estimate_tokens(content)
            if tokens > 200:
                pointer = content[:160] + "…[已裁剪为指针，原始输出见落盘文件]"
                saved += tokens - estimate_tokens(pointer)
                out.append({**msg, "content": pointer})
            else:
                out.append(msg)
        out += tail
        return out, saved
