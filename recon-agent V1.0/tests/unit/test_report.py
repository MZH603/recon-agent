"""报告生成测试（水印 / 结构 / 三格式落盘）。"""
from observability.metrics import TaskMetrics
from output.report import DEGRADED_WATERMARK, INCOMPLETE_WATERMARK, ReconData, render_markdown, save_report


def make_data() -> ReconData:
    return ReconData(
        target="example.com", scan_level=0,
        subdomains=["admin.example.com", "api.example.com"],
        out_of_scope=["partner-company.cn"],
        ips=["93.184.216.34"], c_sectors=["93.184.216.0/24"],
        tech_cards=[{"host": "example.com", "status": 200, "title": "Example",
                     "tech": {"server": {"name": "Nginx", "confidence": 0.9,
                                          "source": "[来源: Header Server]"}}}],
        cves=[{"product": "nginx", "status": "未收录",
               "note": "知识库未收录该产品，禁止推测 CVE"}],
        doubts=["example.com server: Nginx vs Apache [冲突，需人工核实]"],
        degraded=["crt.sh 不可达，子域枚举降级为空"],
        next_steps=[{"command": "recon-agent -t example.com --authorized --profile stealth",
                     "purpose": "L1 探测", "risk": "中", "needs_gate": False}],
    )


def test_render_contains_required_sections():
    md = render_markdown(make_data(), TaskMetrics(), [])
    for section in ("执行摘要", "子域名清单", "存活资产总表", "技术栈明细",
                    "关联资产拓线图", "存疑清单", "降级清单", "下一步行动建议", "原始数据引用"):
        assert section in md
    assert "| 资产 | 标题 | 开放端口 | 中间件 | CMS |" in md   # 标准表格头（含标题列）
    assert "[来源: Header Server]" in md          # HARD: 结论带来源
    assert "仅记录不扫描" in md                    # 关联资产只记录
    assert "禁止推测 CVE" in md                    # 否定证据
    assert "需三级门控确认" not in md              # 本例无 L2 项


def test_alive_and_port_map_populate_table():
    data = make_data()
    data.alive_hosts = ["example.com", "admin.example.com", "api.example.com"]
    data.port_map = {"example.com": [443], "admin.example.com": []}
    md = render_markdown(data, TaskMetrics(), [])
    assert "✅ 存活" in md                                   # 子域名清单状态列
    assert "| example.com | Example | 443 |" in md           # 端口回填 + 标题列
    # 三种端口状态严格区分：真实扫描 / 扫过无开放 / 从未扫过
    assert "无开放端口（L1 扫描完成）" in md                  # admin：扫过但无开放端口
    assert "未探测（需 L1 受控扫描）" in md                   # api：从未扫过 → 待办标记


def test_unscanned_and_dead_status_marks():
    """扫过的主机给结论，没扫过的给待办标记，未解析的给 ❌——三者不可混淆。"""
    data = make_data()
    data.alive_hosts = ["example.com", "api.example.com"]    # admin 未存活
    data.port_map = {"example.com": [80, 443]}
    md = render_markdown(data, TaskMetrics(), [])
    assert "❌ 未解析/未存活" in md                          # admin：子域清单状态
    assert md.count("未探测（需 L1 受控扫描）") == 1         # api：存活但未扫
    assert "无开放端口（L1 扫描完成）" not in md


def test_degraded_watermark_present():
    data = make_data()
    assert DEGRADED_WATERMARK in render_markdown(data, TaskMetrics(), [DEGRADED_WATERMARK])
    assert INCOMPLETE_WATERMARK in render_markdown(
        data, TaskMetrics(), [INCOMPLETE_WATERMARK])  # HARD: 预算耗尽水印置顶


def test_save_report_three_formats(tmp_path):
    paths = save_report(make_data(), TaskMetrics(), [], out_dir=tmp_path)
    assert paths["markdown"].exists() and paths["json"].exists() and paths["csv"].exists()
    assert "example" in paths["markdown"].name
    csv_text = paths["csv"].read_text(encoding="utf-8")
    assert "subdomain" in csv_text and "范围外候选" in csv_text
