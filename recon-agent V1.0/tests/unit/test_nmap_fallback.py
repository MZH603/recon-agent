"""nmap → builtin 降级路径回归（真机演示暴露的跨 Schema 崩溃）。"""
import asyncio

from tools.nmap_tool import PortScanParams, NmapTool
from utils.config import Settings


def test_nmap_falls_back_to_builtin_when_missing(monkeypatch):
    import platforms.tools as pt
    from scripts import sandbox  # noqa: F401 —— 确保独立可导入

    monkeypatch.setattr(pt, "find_tool", lambda name: None if name == "nmap" else None)
    from tools import nmap_tool as nt

    monkeypatch.setattr(nt, "find_tool", lambda name: None)  # nmap 不可用
    settings = Settings()
    settings.REQUEST_DELAY_RANGE = (0.0, 0.0)  # 测试提速（不改变生产默认）
    tool = NmapTool(settings)
    result = asyncio.run(tool.run(PortScanParams(target="example.com", ports="80,443")))
    assert result.success, result.error
    assert result.degraded  # HARD: 降级标注
    assert result.confidence <= 0.6
    assert any("降级" in e for e in result.evidence)
    assert result.data["open_ports"] or result.data["closed"] or result.data["stopped_early"]
