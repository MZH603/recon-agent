"""Recognize completion only in the final standalone assistant body line."""
import re

MARKER = '<task_complete/>'
REMINDER = '请继续推进任务；如缺少输入用 ask_user；已完成时先给出结论，再在正文最后独立一行输出 <task_complete/>。'


def completion_text(content: str) -> tuple[str, bool]:
    lines = content.splitlines()
    nonempty = [index for index, line in enumerate(lines) if line.strip()]
    if not nonempty or lines[nonempty[-1]].strip() != MARKER:
        return content, False
    last = nonempty[-1]
    # Some compatible providers include reasoning tags in content rather than
    # a separate field. An unclosed reasoning block is still not assistant body.
    reasoning = 0
    for tag in re.finditer(r'<\s*(/?)\s*(think|thinking|analysis|reasoning)\b[^>]*>', '\n'.join(lines[:last]), re.I):
        if tag.group(1): reasoning = max(0, reasoning - 1)
        elif not tag.group(0).rstrip().endswith('/>'): reasoning += 1
    if reasoning:
        return content, False
    if lines[last].expandtabs(4).startswith('    '):
        return content, False
    fence = None
    for line in lines[:last + 1]:
        match = re.match(r'^ {0,3}(`{3,}|~{3,})', line)
        if match:
            run = match.group(1)
            if fence is None:
                fence = run
            elif run[0] == fence[0] and len(run) >= len(fence) and not line[match.end():].strip():
                fence = None
    if fence is not None:
        return content, False
    return '\n'.join(lines[:last]).rstrip(), True
