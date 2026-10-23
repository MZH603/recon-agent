"""调用去重（HARD：相同 (目标,工具,参数) 在 TTL 内直接复用缓存，不调 LLM、不执行工具）。"""
from __future__ import annotations

from model.base import NormalizedToolCall
from utils.cache import SQLiteCache, cache_key
from utils.config import Settings, get_settings


class CallDeduplicator:
    """精确哈希去重（v1；语义等价去重需 embedding 小模型，v2 规划，不落地）。"""

    def __init__(self, settings: Settings | None = None, cache: SQLiteCache | None = None) -> None:
        settings = settings or get_settings()
        self._ttl = settings.DEDUP_TTL_SECONDS
        self._enabled = settings.DEDUP_ENABLED
        self._cache = cache

    def should_skip(self, call: NormalizedToolCall, main_target: str) -> tuple[bool, str]:
        """返回 (是否跳过, 原因)；命中缓存说明同样调用近期已成功执行。"""
        if not self._enabled or self._cache is None:
            return False, "disabled"
        key = self._key(call, main_target)
        hit = self._cache.get(key, self._ttl)
        if hit is None:
            return False, "miss"
        return True, f"[缓存命中] 相同调用在 TTL 内已执行（{hit.get('brief', '')[:80]}）"

    def record(self, call: NormalizedToolCall, main_target: str, result_brief: str) -> None:
        """记录一次成功执行，供后续去重命中。"""
        if self._enabled and self._cache is not None:
            self._cache.put(self._key(call, main_target), {"brief": result_brief[:400]})

    @staticmethod
    def _key(call: NormalizedToolCall, main_target: str) -> str:
        args = {k: v for k, v in call.arguments.items() if not k.startswith("_")}
        target = str(args.get("target") or main_target)
        return cache_key(target, call.name, args)
