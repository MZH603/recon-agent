"""统一报告构建器（HARD：L0 流水线与 L2 扫描共用同一渲染规范，禁止旁路格式）。

用法：Builder 逐个注入工具结果 → build_markdown() 得到标准格式报告。
"""
from __future__ import annotations

from observability.metrics import TaskMetrics
from output.report import DEGRADED_WATERMARK, ReconData, render_markdown, save_report
from tools.base import ToolResult


class ReportBuilder:
    """把任意执行路径（L0 流水线 / L2 编排 / MCP）的工具结果装配成标准报告。"""

    def __init__(self, target: str, scan_level: int = 0, strategy_note: str = "") -> None:
        self.data = ReconData(target=target, scan_level=scan_level,
                              strategy_note=strategy_note or f"L{scan_level} 受控采集")

    # ---- 资产面 ----
    def add_subdomains(self, subdomains: list[str], alive: list[str]) -> None:
        """注入子域清单与存活结果（HARD：清单全量入报告，指纹上限不截断清单）。"""
        self.data.subdomains = sorted(set(subdomains))[:100]
        self.data.alive_hosts = sorted(set(alive) | {self.data.target})

    def add_port_scan(self, host: str, result: ToolResult) -> None:
        """注入端口扫描结果（nmap_scan / builtin_port_scan）。"""
        if not result.success:
            self.data.notes.append(f"端口扫描失败 {host}: {result.error[:120]}")
            return
        ports = result.data.get("open_ports", [])
        if ports:
            self.data.port_map[host] = ports
        if result.data.get("stopped_early"):
            self.data.notes.append(f"{host}: 端口扫描因连接失败提前终止（HARD 失败即停）")
        if result.degraded:
            self.data.degraded.append(f"端口扫描 {host} 使用 builtin_socket 降级模式")

    # ---- 指纹面 ----
    def add_tech_card(self, card: dict) -> None:
        """注入指纹卡片（fingerprint / deep_fingerprint），同名主机合并去重。"""
        if card.get("error"):
            self.data.notes.append(f"指纹失败 {card.get('host')}: {card['error'][:120]}")
            return
        host = str(card.get("host", ""))
        self.data.tech_cards = [c for c in self.data.tech_cards if c.get("host") != host]
        self.data.tech_cards.append(card)
        scheme = card.get("scheme", "")
        if scheme and host not in self.data.port_map:
            self.data.port_map[host] = [443] if scheme == "https" else [80]

    def add_tech_cards(self, cards: list[dict]) -> None:
        for card in cards:
            self.add_tech_card(card)

    # ---- L2 结果面 ----
    def add_dir_enum(self, host: str, result: ToolResult) -> None:
        """注入路径枚举结果：命中项带严重度进风险路径，零暴露进正面备注。"""
        if not result.success:
            self.data.notes.append(f"路径枚举失败 {host}: {result.error[:120]}")
            return
        data = result.data or {}
        for found in data.get("found", []):
            self.data.risk_paths.append({
                "target": host, "path": found.get("path", ""),
                "status": found.get("status"), "note": found.get("note", ""),
                "severity": found.get("severity", "—"),
                "leaks": found.get("leaks", []),
            })
        high = data.get("high_count", 0)
        if high:
            self.data.notes.append(f"{host}: {high} 条 High 级泄露发现（证据哈希见数据，需人工复核定性）")
        if not data.get("found"):
            self.data.notes.append(f"{host}: {data.get('checked', 0)} 条敏感路径零暴露（正面项）")
        if data.get("stopped_early"):
            self.data.notes.append(f"{host}: 路径枚举因连接失败提前终止（HARD）")

    def add_script_probe(self, host: str, result: ToolResult) -> None:
        """注入沙箱探针结果（响应头等），解析键值对进备注与降级/缺失清单。"""
        if not result.success:
            self.data.notes.append(f"沙箱探针失败 {host}: {result.error[:120]}")
            return
        self.data.notes.append(f"沙箱探针 {host}: exit={result.data.get('exit_code', 0)}（AST+Bandit 校验通过）")
        for line in result.stdout.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            if key in ("strict-transport-security", "content-security-policy", "x-content-type-options") \
                    and value.strip().lower() in ("none", ""):
                self.data.doubts.append(f"{host}: 缺失 {key} [未确认，建议人工核实]")

    def add_note(self, note: str) -> None:
        """追加采集备注。"""
        self.data.notes.append(note)

    def add_degraded(self, item: str) -> None:
        self.data.degraded.append(item)

    # ---- 输出 ----
    def build_markdown(self, metrics: TaskMetrics | None = None, watermarks: list[str] | None = None) -> str:
        """渲染标准报告；HARD：存在降级项时自动附加降级水印（不依赖调用方）。"""
        marks = list(watermarks or [])
        if self.data.degraded and DEGRADED_WATERMARK not in marks:
            marks.append(DEGRADED_WATERMARK)
        return render_markdown(self.data, metrics or TaskMetrics(), marks)

    def save(self, metrics: TaskMetrics | None = None, watermarks: list[str] | None = None,
             out_dir=None) -> dict:
        return save_report(self.data, metrics or TaskMetrics(), watermarks or [], out_dir)
