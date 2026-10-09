"""离线验证 nmap → builtin 降级参数转换与降级标注。"""
import asyncio

from tools.nmap_tool import PortScanParams, NmapTool
from utils.config import Settings


def test_nmap_falls_back_to_builtin_when_missing(monkeypatch):
    from tools import nmap_tool as nt
    probes, closed = [], []

    async def resolve(host, port):
        assert host == 'example.com' and port is None
        return [(2, 1, 6, '', ('192.0.2.1', 0))]

    class Writer:
        def close(self):
            closed.append(80)

    async def connect(address, port):
        assert address == '192.0.2.1'
        probes.append(port)
        if port == 443:
            raise ConnectionRefusedError
        return None, Writer()

    monkeypatch.setattr(nt, "find_tool", lambda name: None)
    monkeypatch.setattr('platforms.sync_worker.resolve_addresses', resolve)
    monkeypatch.setattr('tools.builtin.port_scan.asyncio.open_connection', connect)
    settings = Settings()
    settings.REQUEST_DELAY_RANGE = (0.0, 0.0)  # 测试提速（不改变生产默认）
    tool = NmapTool(settings)
    result = asyncio.run(tool.run(PortScanParams(target="example.com", ports="80,443")))
    assert result.success, result.error
    assert result.degraded  # HARD: 降级标注
    assert result.confidence <= 0.6
    assert any("降级" in e for e in result.evidence)
    assert result.data == {'open_ports': [80], 'closed': [443], 'stopped_early': False}
    assert probes == [80, 443] and closed == [80]
