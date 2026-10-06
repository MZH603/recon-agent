"""上下文管理（三层压缩：Raw > Compaction > Summarization；HARD：大输出不进 Prompt）。"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from efficiency.context_trimmer import ContextTrimmer, estimate_tokens
from efficiency.template_compressor import compress
from model.base import LLMResponse, NormalizedToolCall
from platforms.paths import get_cache_dir
from tools.base import ToolResult
from utils.config import Settings, get_settings


class ContextManager:
    """维护消息列表：注入工具结果（超阈值落盘）、预算触发时裁剪。"""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._messages: list[dict] = []
        self._trimmer = ContextTrimmer(self._settings.CONTEXT_BUDGET)
        self.trimmed_tokens = 0
        self._task_id = time.strftime("%Y%m%d_%H%M%S")

    @property
    def messages(self) -> list[dict]:
        """当前消息列表（供模型调用）。"""
        return self._messages

    def set_system(self, content: str) -> None:
        """设置/刷新 system 消息（保持首条稳定前缀，供 Prompt Cache 命中）。"""
        if self._messages and self._messages[0].get("role") == "system":
            self._messages[0] = {"role": "system", "content": content}
        else:
            self._messages.insert(0, {"role": "system", "content": content})

    def add_user(self, content: str) -> None:
        """追加用户消息。"""
        self._messages.append({"role": "user", "content": content})

    def add_assistant_response(self, resp: LLMResponse) -> None:
        """保留 assistant 原始消息结构（含 tool_calls，供原生 Tool Use 协议回填）。"""
        message: dict = {"role": "assistant", "content": resp.content}
        if resp.tool_calls:
            message["tool_calls"] = [
                {"id": c.id, "type": "function",
                 "function": {"name": c.name, "arguments": json.dumps(c.arguments, ensure_ascii=False)}}
                for c in resp.tool_calls
            ]
        self._messages.append(message)

    def add_tool_result(self, call: NormalizedToolCall, result: ToolResult, native: bool) -> str:
        """注入工具结果：模板压缩 + 超阈值落盘（HARD：>1500 tokens 只留摘要指针）。"""
        rendered, raw_path = self._render_result(call.name, result)
        if native:
            self._messages.append({"role": "tool", "tool_call_id": call.id, "content": rendered})
        else:
            self._messages.append({"role": "user", "content": rendered})
        return raw_path

    def maybe_compact(self) -> int:
        """上下文用量超 70% 触发裁剪（HARD：绝不拖到 90%+）。返回本次节省 token。"""
        limit = int(self._settings.CONTEXT_BUDGET * self._settings.COMPACT_TRIGGER_RATIO)
        trimmed, saved = self._trimmer.trim(self._messages, limit)
        if saved > 0:
            self._messages = trimmed
            self.trimmed_tokens += saved
        return saved

    def estimate_total(self) -> int:
        """当前上下文 token 粗估。"""
        return sum(estimate_tokens(str(m.get("content") or "")) for m in self._messages)

    def _render_result(self, tool_name: str, result: ToolResult) -> tuple[str, str]:
        """渲染结果文本；超阈值时原始输出落盘并返回指针。"""
        compacted = None
        if self._settings.TEMPLATE_COMPRESSION and result.success and result.stdout:
            compacted = compress(tool_name, result.stdout)
        body = json.dumps(compacted, ensure_ascii=False) if compacted else (
            result.data and json.dumps(result.data, ensure_ascii=False) or result.stdout
        )
        header = (
            f"<tool_result tool=\"{result.name}\" success=\"{str(result.success).lower()}\" "
            f"confidence=\"{result.confidence:.2f}\""
            + (" degraded=\"true\"" if result.degraded else "")
            + (f" error=\"{result.error[:200]}\"" if result.error else "")
            + ">"
        )
        evidence = "；".join(result.evidence[:5])
        content = f"{header}\n{str(body)[:6000]}\n证据: {evidence or '无'}\n</tool_result>"
        raw_path = ""
        if estimate_tokens(content) > self._settings.COMPRESS_THRESHOLD:
            raw_path = self._dump_raw(tool_name, content)
            pointer = (
                f"{header}\n[输出过大已落盘] 摘要: success={result.success}, "
                f"data_keys={list(result.data)[:6]}\n完整内容: {raw_path}\n证据: {evidence or '无'}\n</tool_result>"
            )
            return pointer, raw_path
        return content, raw_path

    def _dump_raw(self, tool_name: str, content: str) -> str:
        """原始输出落盘（Compaction 层，可按需恢复）。"""
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
        directory = get_cache_dir() / f"task_{self._task_id}"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{tool_name}_{digest}.txt"
        path.write_text(content, encoding="utf-8", newline="")
        return str(path)
