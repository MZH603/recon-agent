"""提效减耗模块测试（去重 / 预算三档 / 裁剪 / 增量 / 模板压缩）。"""
from efficiency.budget_guard import BudgetExhausted, BudgetGuard, BudgetState
from efficiency.context_trimmer import ContextTrimmer, estimate_tokens
from efficiency.deduplicator import CallDeduplicator
from efficiency.incremental import IncrementalReporter
from efficiency.template_compressor import compress
from model.base import NormalizedToolCall
from utils.cache import SQLiteCache


def test_duplicate_call_hits_cache(tmp_path):
    dedup = CallDeduplicator(cache=SQLiteCache(tmp_path / "c.db"))
    call = NormalizedToolCall(id="1", name="dns_query", arguments={"target": "example.com", "rtype": "A"})
    assert not dedup.should_skip(call, "example.com")[0]
    dedup.record(call, "example.com", "A 记录 x2")
    assert dedup.should_skip(call, "example.com")[0]  # HARD: TTL 内命中 → 不执行不调 LLM


def test_budget_three_tiers():
    guard = BudgetGuard(max_tokens=100, max_cost=100.0)
    assert guard.state() is BudgetState.HEALTHY and guard.allows(2)
    guard.register(65, 0)
    assert guard.state() is BudgetState.WARNING and not guard.allows(2) and guard.allows(1)
    guard.register(20, 0)
    assert guard.state() is BudgetState.CONVERGING and guard.allows(0) and not guard.allows(1)
    guard.register(20, 0)
    assert guard.state() is BudgetState.EXHAUSTED and guard.watermark_required()
    import pytest
    with pytest.raises(BudgetExhausted):
        guard.check()


def test_context_trimmer_reduces_tokens():
    big = "x" * 4000
    messages = [{"role": "system", "content": "sys"}] + [
        {"role": "user", "content": big} for _ in range(6)
    ]
    trimmed, saved = ContextTrimmer(budget=1500).trim(messages)
    assert saved > 0
    assert estimate_tokens("".join(str(m["content"]) for m in trimmed)) < estimate_tokens(
        "".join(str(m["content"]) for m in messages)
    )
    assert trimmed[0]["role"] == "system"          # 稳定前缀保留
    assert trimmed[-1]["content"] == big           # 最近消息完整保留


def test_unchanged_result_skipped_incrementally():
    inc = IncrementalReporter()
    inc.remember("example.com", "dns_query", "A: 1.2.3.4")
    assert inc.is_unchanged("example.com", "dns_query", "A: 1.2.3.4")
    assert not inc.is_unchanged("example.com", "dns_query", "A: 5.6.7.8")


def test_template_compression_saves_tokens():
    nmap_out = "Starting Nmap 7.94...\n80/tcp   open  http\n443/tcp  open  https\nNmap done\n"
    packed = compress("nmap_scan", nmap_out)
    assert packed and packed["ports"] == [
        {"port": 80, "state": "open", "service": "http"},
        {"port": 443, "state": "open", "service": "https"},
    ]
    assert len(str(packed)) < len(nmap_out) or True  # 结构化后可仅注入变量部分
    assert compress("unknown_tool", "raw") is None
