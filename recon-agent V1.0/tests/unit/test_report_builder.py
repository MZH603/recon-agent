"""报告构建器 + 深度指纹测试。"""
import asyncio

from output.report_builder import ReportBuilder
from tools.base import ToolResult
from tools.deep_fingerprint import DeepFingerprintParams, DeepFingerprintTool
from tools.techniques.error_page import match_error_page
from utils.config import get_settings


def test_builder_produces_standard_sections():
    builder = ReportBuilder("example.com", scan_level=2, strategy_note="L2 测试")
    builder.add_subdomains(["b.example.com", "a.example.com", "example.com"],
                           ["a.example.com", "example.com"])
    builder.add_port_scan("example.com", ToolResult(
        name="nmap_scan", success=True,
        data={"open_ports": [80, 443], "stopped_early": True}, degraded=True))
    builder.add_tech_card({"host": "example.com", "status": 200, "title": "示例大学",
                           "scheme": "https", "confidence": 0.9,
                           "tech": {"server": {"name": "Nginx", "confidence": 0.9,
                                               "source": "[来源: Header Server]"}}})
    builder.add_dir_enum("admin.example.com", ToolResult(
        name="dir_enum", success=True,
        data={"checked": 12, "found": [{"path": "/robots.txt", "status": 200, "note": "可访问"}]}))
    builder.add_note("OneForAll 对照产出 0（环境受限）")
    md = builder.build_markdown()
    for section in ("子域名清单", "存活资产总表", "风险路径（L2 枚举命中，含泄露嗅探分级）"):
        assert section in md
    assert "| example.com | 示例大学 | 80, 443 |" in md
    assert "| admin.example.com | /robots.txt | 200 | — | 可访问 |" in md  # 无严重度数据 → —
    assert "[降级模式]" in md and "提前终止" in md
    assert "✅ 存活" in md and "❌ 未解析/未存活" in md


def test_builder_zero_exposure_recorded_as_positive():
    builder = ReportBuilder("example.com", scan_level=2)
    builder.add_dir_enum("example.com", ToolResult(
        name="dir_enum", success=True, data={"checked": 40, "found": []}))
    assert "40 条敏感路径零暴露" in builder.data.notes[-1]


def test_deep_fingerprint_registered_and_gated():
    from gate.scan_gate import ScanGate
    from model.base import NormalizedToolCall
    from tools.registry import build_default

    gate = ScanGate("example.com", batch_mode=True, is_tty=False)  # 非交互禁 L2
    registry = build_default(get_settings(), gate, "example.com")
    result = asyncio.run(registry.execute(NormalizedToolCall(
        id="1", name="deep_fingerprint",
        arguments={"target": "sub.example.com", "include_baseline": False})))
    assert not result.success and "[门控]" in result.error  # HARD: 未解锁 L2 拒绝
