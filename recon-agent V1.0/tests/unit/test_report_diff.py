"""接管检测纯函数 + 报告 diff/Mermaid 测试。"""
from observability.metrics import TaskMetrics
from output.diff import diff_reports
from output.report import ReconData, render_markdown
from tools.takeover_check import match_takeover


def test_match_takeover_signatures():
    assert match_takeover("There isn't a GitHub Pages site here.") == "GitHub Pages"
    assert match_takeover("404 Web Site not found.") == "Azure Web Apps"
    assert match_takeover("<html>normal content</html>") is None


def _old_report() -> dict:
    return {
        "subdomains": ["a.example.com", "old.example.com"],
        "ips": ["1.1.1.1"],
        "tech_cards": [
            {"host": "example.com", "tech": {"server": {"name": "Nginx"}}},
            {"host": "a.example.com", "tech": {"js库": {"name": "jQuery"}}},
        ],
    }


def _new_data() -> ReconData:
    return ReconData(
        target="example.com",
        subdomains=["a.example.com", "b.example.com"],
        ips=["1.1.1.1", "2.2.2.2"],
        tech_cards=[
            {"host": "example.com", "tech": {"server": {"name": "Nginx"},
                                             "js库": {"name": "jQuery"}}},
            {"host": "a.example.com", "tech": {}},
        ],
    )


def test_diff_reports_finds_changes():
    md = diff_reports(_old_report(), _new_data())
    assert "b.example.com" in md and "old.example.com" in md     # 子域增/删
    assert "2.2.2.2" in md                                        # IP 新增
    assert "+jQuery" in md or "+js库" in md                       # 技术栈新增
    assert "增量对比" in md


def test_diff_reports_no_change():
    old = _old_report()
    new = _new_data()
    new.subdomains = list(old["subdomains"])
    new.ips = list(old["ips"])
    new.tech_cards = old["tech_cards"]
    assert "无实质变化" in diff_reports(old, new)


def test_report_contains_mermaid_topology():
    data = _new_data()
    data.out_of_scope = ["partner.com"]
    md = render_markdown(data, TaskMetrics(), [])
    assert "```mermaid" in md and "graph TD" in md
    assert 'T["example.com"]' in md
    assert "b.example.com" in md
    assert "范围外仅记录" in md
