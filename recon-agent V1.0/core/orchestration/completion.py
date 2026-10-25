"""Recognize completion only in the final standalone assistant body line."""
import re

MARKER = '<task_complete/>'
REMINDER = '请继续推进任务；如缺少输入用 ask_user；已完成时先给出结论，再在正文最后独立一行输出 <task_complete/>。'


def _count_reasoning_blocks(text: str) -> int:
    """Count unclosed reasoning blocks in text."""
    reasoning = 0
    # Match opening tags: <thinking>, <thinking attr="value">, <think>, etc.
    # Match closing tags: </thinking>, </think>, etc.
    # Match self-closing: <thinking />
    for tag in re.finditer(r'<\s*(/?)\s*(think|thinking|analysis|reasoning)\b[^>]*>', text, re.I):
        is_closing = bool(tag.group(1))
        tag_content = tag.group(0)
        is_self_closing = tag_content.rstrip().endswith('/>')
        if is_self_closing:
            continue
        if is_closing:
            reasoning = max(0, reasoning - 1)
        else:
            reasoning += 1
    return reasoning


def _has_unclosed_fence(lines: list[str], up_to: int) -> bool:
    """Check if there's an unclosed markdown code fence."""
    fence = None
    for i, line in enumerate(lines[:up_to + 1]):
        match = re.match(r'^ {0,3}(`{3,}|~{3,})', line)
        if match:
            run = match.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not line[match.end():].strip():
                fence = None
    return fence is not None


def completion_text(content: str) -> tuple[str, bool]:
    lines = content.splitlines()
    nonempty = [index for index, line in enumerate(lines) if line.strip()]
    if not nonempty or lines[nonempty[-1]].strip() != MARKER:
        return content, False
    last = nonempty[-1]
    
    # Check for unclosed reasoning blocks before the marker
    before_marker = '\n'.join(lines[:last])
    if _count_reasoning_blocks(before_marker) > 0:
        return content, False
    
    # Marker must not be indented (code block continuation)
    if lines[last].expandtabs(4).startswith('    '):
        return content, False
    
    # Check for unclosed markdown code fence
    if _has_unclosed_fence(lines, last):
        return content, False
    
    return '\n'.join(lines[:last]).rstrip(), True
