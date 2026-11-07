"""流水线情报扩容编排（L0 被动）：测绘引擎 / 组织情报 / 代码泄漏 / dorking。

每个通道独立降级：未配置 Key → 报告声明「未启用」；失败 → notes 记录不中断。
全部通道零目标基础设施接触（仅第三方 API/搜索引擎；org_intel 含主站 1 次只读 GET）。
"""
from __future__ import annotations

from output.report import ReconData
from utils.config import Settings

MAPPING_SOURCES = ("fofa", "quake", "zoomeye", "shodan", "censys", "hunter",
                   "netlas", "virustotal", "securitytrails", "weibu", "threatbook",
                   "binaryedge")


def _mapping_keys(settings: Settings) -> list[str]:
    """返回已配置 Key 的测绘源（key 惯例：settings.{NAME}_API_KEY）。"""
    return [s for s in MAPPING_SOURCES
            if (getattr(settings, f"{s.upper()}_API_KEY", "") or "").strip()]


async def expand_intel(data: ReconData, settings: Settings) -> None:
    """在 enrich_recon 后追加外部情报扩容（失败显式记录，不中断流水线）。"""
    from utils.logger import warn

    # ---- 通道 1：测绘引擎（有 key 才查询；逐源声明未启用项）----
    configured = _mapping_keys(settings)
    if configured:
        try:
            from tools.builtin.datasource_query import DataSourceQueryParams, DataSourceQueryTool
            result = await DataSourceQueryTool(settings).run(
                DataSourceQueryParams(target=data.target, sources=configured, size=100))
            if result.success:
                data.mapping_assets = result.data.get("assets", [])
                data.notes.append(
                    f"测绘引擎: {result.data.get('total_assets', 0)} 条资产"
                    f"（来源 {', '.join(configured)}）")
                if result.data.get("errors"):
                    data.notes.append(f"测绘引擎部分源失败: {'; '.join(result.data['errors'])[:200]}")
            else:
                data.notes.append(f"测绘引擎查询失败: {result.error[:120]}")
        except (OSError, ValueError, RuntimeError) as exc:
            data.notes.append(f"测绘引擎通道异常（不中断）: {exc}")
    else:
        data.notes.append(
            "测绘引擎未启用（缺 API Key：FOFA/Quake/Shodan/Hunter/Netlas/VirusTotal/SecurityTrails 等任一）")

    # ---- 通道 2：组织与人员情报（四通道自降级，始终运行）----
    try:
        from tools.builtin.org_intel import OrgIntelParams, OrgIntelTool
        result = await OrgIntelTool(settings).run(OrgIntelParams(target=data.target, ips=data.ips[:3]))
        if result.success:
            org = result.data
            data.org_info = {
                "emails": org.get("emails", []),
                "role_account_candidates": org.get("role_account_candidates", []),
                "whois_org": org.get("whois_org", ""),
                "icp": org.get("icp", {}),
                "asn": org.get("asn", []),
                "enterprise": org.get("org_info", {}),
            }
            if org.get("emails"):
                data.notes.append(f"邮箱采集: {len(org['emails'])} 个（主站/WHOIS）")
            if org.get("notes"):
                data.notes.append(f"组织情报通道备注: {'; '.join(org['notes'])[:200]}")
        else:
            data.notes.append(f"组织情报失败: {result.error[:120]}")
    except (OSError, ValueError, RuntimeError) as exc:
        data.notes.append(f"组织情报通道异常（不中断）: {exc}")

    # ---- 通道 3：代码仓库泄漏（有 token 才查询）----
    if (settings.GITHUB_API_KEY or "").strip() or (settings.GITEE_API_KEY or "").strip():
        try:
            from tools.builtin.code_leak_search import CodeLeakParams, CodeLeakSearchTool
            result = await CodeLeakSearchTool(settings).run(
                CodeLeakParams(target=data.target))
            if result.success:
                data.code_leaks = result.data.get("items", [])
                high = result.data.get("high_count", 0)
                data.notes.append(
                    f"代码泄漏检索: {result.data.get('total_hits', 0)} 条命中"
                    f"（High {high}，密钥已脱敏）")
                data.doubts += [
                    f"[代码泄漏] {item.get('repo','')}/{item.get('path','')}: "
                    f"{', '.join(s['type'] for s in item.get('secrets', []))} [未确认，建议人工核实]"
                    for item in data.code_leaks if item.get("secrets")
                ][:5]
            else:
                data.notes.append(f"代码泄漏检索失败: {result.error[:120]}")
        except (OSError, ValueError, RuntimeError) as exc:
            data.notes.append(f"代码泄漏通道异常（不中断）: {exc}")
    else:
        data.notes.append("代码泄漏检索未启用（缺 GITHUB_API_KEY/GITEE_API_KEY）")

    # ---- 通道 4：搜索引擎 dorking（无 Key 后端链，始终尝试）----
    try:
        from tools.builtin.dork_search import DorkSearchParams, DorkSearchTool
        result = await DorkSearchTool(settings).run(DorkSearchParams(target=data.target))
        if result.success:
            data.dork_findings = result.data.get("results", [])
            high = result.data.get("high_count", 0)
            data.notes.append(
                f"dorking: {result.data.get('queries_run', 0)}/{result.data.get('budget', 0)} 查询"
                f"，High 命中 {high}"
                + (f"；{result.data.get('quality_note')}" if result.data.get("quality_note") else ""))
        else:
            data.notes.append(f"dorking 失败: {result.error[:120]}")
    except (OSError, ValueError, RuntimeError) as exc:
        data.notes.append(f"dorking 通道异常（不中断）: {exc}")

    for note in data.notes[-6:]:
        warn(note)
