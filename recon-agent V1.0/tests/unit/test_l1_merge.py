"""L0→L1 合并（v1.1）回归守卫：级别 0 = 未解锁不采集；profile 别名；流水线门控。"""
import asyncio

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.registry import build_default
from utils.config import get_settings


def test_level0_blocks_all_recon_tools():
    """HARD: 级别 0 = 未解锁——原 L0 工具（min_level=1）一律被门控拒绝。"""
    settings = get_settings()
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, requested_level=0)
    assert gate.current_level() == 0
    registry = build_default(settings, gate, "example.com")
    for tool_name in ("subdomain_enum", "fingerprint", "datasource_query", "dns_query"):
        result = asyncio.run(registry.execute(NormalizedToolCall(
            id=f"t-{tool_name}", name=tool_name, arguments={"target": "sub.example.com"})))
        assert not result.success and "[门控]" in result.error, tool_name


def test_profile_passive_alias_maps_to_l1():
    """--profile passive 为兼容别名 → L1（基础侦察）。"""
    from cli.main import PROFILE_LEVELS, _resolve_level
    assert PROFILE_LEVELS["passive"] == 1 and PROFILE_LEVELS["stealth"] == 1
    assert _resolve_level("passive", None) == 1
    assert _resolve_level("stealth", None) == 1


def test_l1_grant_via_cli_args():
    """启动参数显式声明 = L1 授权（既有语义），batch 下生效。"""
    gate = ScanGate("example.com", batch_mode=True, is_tty=False, requested_level=1)
    assert gate.current_level() == 1


def test_pipeline_level0_refuses_without_network(tmp_path, monkeypatch):
    """run_pipeline 在级别 0 立即返回 2（门控先行，零网络触碰）。"""
    from cli import pipeline

    def forbidden(*args, **kwargs):
        raise AssertionError("级别 0 不允许任何出站调用")

    monkeypatch.setattr("collectors.asset_expander.expand_assets", forbidden)
    code = asyncio.run(pipeline.run_pipeline(
        target="example.com", settings=get_settings(), batch=True, is_tty=False,
        requested_level=0, model_override=None, output_format="markdown",
        output_dir=str(tmp_path)))
    assert code == 2
