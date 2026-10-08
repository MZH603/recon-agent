"""Line-oriented streaming presentation; observations never execute model output."""
from __future__ import annotations

import json
import re
import unicodedata
from time import monotonic

from rich.console import Console, Group
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from rich.cells import cell_len


def safe_text(text: str) -> str:
    """Remove terminal escape sequences, including incomplete split sequences."""
    text = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)', '', str(text))
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = re.sub(r'\x1b(?:\[[0-?]*[ -/]*)?$', '', text)
    text = re.sub(r'\x1b.', '', text)
    return ''.join(c for c in text if c in '\n\t' or unicodedata.category(c) not in ('Cc', 'Cf', 'Cs'))


def visible_content(raw: str) -> str:
    """Withhold tag prefixes, tool protocol blocks and tagged reasoning across chunks."""
    visible, position, hidden = [], 0, None
    while position < len(raw):
        if hidden:
            close = re.search(r'</\s*' + re.escape(hidden) + r'\s*>', raw[position:], re.I)
            if close is None:
                break
            position += close.end()
            hidden = None
            continue
        opening = raw.find('<', position)
        if opening < 0:
            visible.append(raw[position:])
            break
        visible.append(raw[position:opening])
        end = raw.find('>', opening)
        if end < 0:
            break
        tag = raw[opening + 1:end].strip().lower().split()[0] if raw[opening + 1:end].strip() else ''
        if tag in ('tool_call', 'tool_calls', 'think', 'thinking', 'analysis', 'reasoning'):
            hidden = tag
        elif tag not in ('/tool_call', '/tool_calls', '/think', '/thinking', '/analysis', '/reasoning'):
            visible.append(raw[opening:end + 1])
        position = end + 1
    return safe_text(''.join(visible))


def control_text(arguments: str, field: str) -> str:
    """Decode only the available JSON string prefix, never raw tool arguments."""
    match = re.search(r'(?<!\\)"' + field + r'"\s*:\s*"', arguments)
    if match is None:
        return ''
    start = match.end()
    position = start
    while position < len(arguments):
        char = arguments[position]
        if char == '"':
            break
        if char == '\\':
            if position + 1 >= len(arguments):
                break
            if arguments[position + 1] == 'u':
                if position + 6 > len(arguments):
                    break
                escape = arguments[position + 2:position + 6]
                if not re.fullmatch('[0-9a-fA-F]{4}', escape):
                    break
                codepoint = int(escape, 16)
                if 0xD800 <= codepoint <= 0xDBFF:
                    if position + 12 > len(arguments) or not re.fullmatch(
                            r'\\u[dD][c-fC-F][0-9a-fA-F]{2}', arguments[position + 6:position + 12]):
                        break
                    position += 12
                    continue
                position += 6
                continue
            position += 2
            continue
        position += 1
    try:
        return visible_content(json.loads('"' + arguments[start:position] + '"'))
    except (ValueError, TypeError):
        return ''


class SessionProgress:
    """A transient bottom loading line, committed dialogue lines, and plain pipe output."""
    def __init__(self, console: Console | None = None, *, is_tty=True):
        self.console = console or Console(highlight=False)
        self.animated = bool(is_tty and self.console.is_terminal and not self.console.is_dumb_terminal)
        self.started = monotonic()
        self.label = '等待模型'
        self.line = ''
        self.slots = {}
        self.shown = set()
        self.in_model = False
        self.spinner = Spinner('dots')
        self.active_key = None
        self.live = Live(console=self.console, get_renderable=self._render,
                         transient=True, refresh_per_second=8) if self.animated else None

    def _render(self):
        self.spinner.update(text=Text(f'{self.label} · {monotonic() - self.started:.1f}s'))
        return Group(Text(self.line), self.spinner) if self.line else self.spinner

    def __enter__(self):
        if self.live:
            self.live.start(refresh=True)
        else:
            self.console.print('等待模型…', markup=False)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.in_model:
            self._end_model(success=False)
        if self.live:
            self.live.stop()
        self._flush_line()

    def _write(self, text):
        if not text:
            return
        if self.animated:
            self.line += text
            while '\n' in self.line:
                complete, self.line = self.line.split('\n', 1)
                self.console.print(Text(complete))
            # Commit long physical lines before Live can crop them out of the viewport.
            while cell_len(self.line) > max(1, self.console.width):
                size = 0
                while size < len(self.line) and cell_len(self.line[:size + 1]) <= max(1, self.console.width):
                    size += 1
                size = max(1, size)
                complete, self.line = self.line[:size], self.line[size:]
                self.console.print(Text(complete))
            self.live.refresh()
        else:
            self.console.print(text, markup=False, highlight=False, end='', soft_wrap=True)
            self.console.file.flush()
            self.line = (self.line + text).rsplit('\n', 1)[-1]

    def _flush_line(self):
        if self.line:
            line, self.line = self.line, ''
            if self.animated:
                self.console.print(Text(line))
            else:
                self.console.print()

    def _note(self, text):
        self._flush_line()
        self.console.print(safe_text(text), markup=False, highlight=False)

    def _preview(self, key, value):
        slot = self.slots[key]
        previous = slot.get('shown', '')
        if not value.startswith(previous):
            return  # An invalid prefix is not a correction or an executable response.
        delta = value[len(previous):]
        if delta:
            if self.active_key != key:
                self._flush_line()
                self._write('模型回复（未验证）: ')
                self.active_key = key
            self._write(delta)
            slot['shown'] = value

    def _end_model(self, success):
        if not self.in_model:
            return
        self._flush_line()
        values = [s.get('shown', '') for s in self.slots.values() if s.get('shown')]
        if success:
            self.shown.update(values)
        elif values:
            self._note('模型回复未完成；已显示片段不能作为完整结果。')
        self.in_model = False
        self.label = '处理中'

    def was_shown(self, text):
        return visible_content(text) in self.shown

    def __call__(self, event):
        kind = event['kind']
        if kind == 'model_start':
            self._end_model(success=True)
            self.slots = {}
            self.active_key = None
            self.in_model = True
            self.label, self.started = '等待模型', monotonic()
        elif kind == 'delta':
            delta = event['delta']
            if delta.kind == 'content':
                key = ('content', 0)
                slot = self.slots.setdefault(key, {'raw': '', 'shown': ''})
                slot['raw'] += delta.content
                self._preview(key, visible_content(slot['raw']))
            elif delta.kind == 'tool':
                key = ('tool', delta.index)
                slot = self.slots.setdefault(key, {'raw': '', 'name': '', 'shown': ''})
                slot['name'] += delta.name
                slot['raw'] += delta.arguments
                field = {'finish_task': 'answer', 'ask_user': 'question'}.get(slot['name'])
                if field:
                    self._preview(key, control_text(slot['raw'], field))
            self.label = '模型回复中'
        elif kind == 'model_end':
            self._end_model(event.get('success', False))
        elif kind == 'tool_start':
            self.label, self.started = f"工具 {safe_text(event['name'])} 执行中", monotonic()
            self._note(self.label)
        elif kind == 'tool_end':
            outcome = '成功' if event.get('success') else '失败/中断'
            self._note(f"工具 {event['name']} {outcome} · {event.get('elapsed', 0):.1f}s")
            self.label = '处理中'
        elif kind in ('retry', 'fallback'):
            self.label = '模型重试中' if kind == 'retry' else '切换备用模型'
            self._note(self.label)
        elif kind == 'plan':
            self._note('计划: ' + event['text'])
        elif kind == 'pause':
            self.label = '等待回复'
        if self.live and self.live.is_started:
            self.live.refresh()
