"""系统安全工具发现：扫描目标环境可用的安全工具，构建能力清单。

Agent 启动时调用，将可用工具注入 System Prompt，
LLM 据此决定优先调用哪个系统工具、何时降级为编写临时脚本。
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field


@dataclass
class SystemTool:
    """系统工具条目。"""
    name: str
    path: str
    capabilities: list[str] = field(default_factory=list)
    priority: int = 5  # 1=首选


# 工具 → 能力映射（侦察任务 → 最适合的系统工具）
SECURITY_TOOL_DB: dict[str, dict] = {
    # ── 端口与服务 ──
    "nmap": {"capabilities": ["port_scan", "service_version", "os_detect", "script_scan"], "priority": 1},
    "masscan": {"capabilities": ["fast_port_scan"], "priority": 2},
    # ── Web 指纹 ──
    "whatweb": {"capabilities": ["web_fingerprint", "cms_detect", "tech_stack"], "priority": 1},
    "wappalyzer": {"capabilities": ["web_fingerprint", "tech_stack"], "priority": 2},
    # ── HTTP 探测 ──
    "curl": {"capabilities": ["http_request", "header_analysis", "content_fetch"], "priority": 1},
    "httpx": {"capabilities": ["probe", "tech_detect", "status_code"], "priority": 1},
    # ── 子域枚举 ──
    "subfinder": {"capabilities": ["subdomain_enum"], "priority": 1},
    "amass": {"capabilities": ["subdomain_enum", "dns_enum"], "priority": 2},
    # ── 路径枚举 ──
    "dirb": {"capabilities": ["dir_enum"], "priority": 1},
    "gobuster": {"capabilities": ["dir_enum", "vhost_enum"], "priority": 1},
    "ffuf": {"capabilities": ["dir_enum", "fuzz"], "priority": 1},
    # ── WAF 检测 ──
    "wafw00f": {"capabilities": ["waf_detect"], "priority": 1},
    # ── DNS ──
    "dig": {"capabilities": ["dns_query"], "priority": 1},
    "host": {"capabilities": ["dns_query"], "priority": 2},
    "nslookup": {"capabilities": ["dns_query"], "priority": 3},
    # ── WHOIS ──
    "whois": {"capabilities": ["whois_query"], "priority": 1},
    # ── SSL/TLS ──
    "sslscan": {"capabilities": ["ssl_scan"], "priority": 1},
    "testssl.sh": {"capabilities": ["ssl_scan"], "priority": 2},
    # ── 漏洞扫描 ──
    "nuclei": {"capabilities": ["vuln_scan", "cve_scan"], "priority": 1},
    "nikto": {"capabilities": ["web_vuln_scan"], "priority": 2},
}


def discover_system_tools() -> dict[str, SystemTool]:
    """扫描 PATH 中的安全工具，返回按优先级排序的能力清单。"""
    found: dict[str, SystemTool] = {}
    for name, info in SECURITY_TOOL_DB.items():
        path = shutil.which(name)
        if path:
            found[name] = SystemTool(
                name=name, path=path,
                capabilities=info["capabilities"],
                priority=info["priority"],
            )
    # 按优先级排序
    return dict(sorted(found.items(), key=lambda x: x[1].priority))


def capability_summary(tools: dict[str, SystemTool]) -> str:
    """生成人类可读的能力摘要（注入 System Prompt）。"""
    if not tools:
        return "（系统未发现安全工具，将使用内置实现或编写临时脚本）"
    lines = []
    for name, tool in tools.items():
        caps = ", ".join(tool.capabilities)
        lines.append(f"  {name} ({tool.path}): {caps}")
    return "\n".join(lines)
