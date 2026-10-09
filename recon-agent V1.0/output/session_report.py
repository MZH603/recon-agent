"""Adapt durable evidence to standard reports and preserve the entire audit state."""
from __future__ import annotations
import json
from ipaddress import ip_address
from uuid import uuid4
from observability.metrics import TaskMetrics
from output.report import save_report, INCOMPLETE_WATERMARK, DEGRADED_WATERMARK
from output.report_builder import ReportBuilder
from tools.base import ToolResult
from tools.builtin.dns_query import RTYPE_CODES
from output.tool_report import WORKSPACE_TOOLS, apply_tool_report

DNS_TYPES = {code: name for name, code in RTYPE_CODES.items()}


def _observations(state):
    current = list(state.get('results', []))
    by_id = {r['execution_id']: r for r in current if r.get('execution_id')}
    results, known = [], set()
    # The durable journal spans tasks; the current task's result list may be reset.
    # Preserve journal chronology before appending results not yet journaled.
    for entry in state.get('executions', []):
        identifier = entry.get('execution_id')
        value = by_id.get(identifier) or entry.get('result')
        if value and identifier not in known:
            results.append({**value, 'execution_id': identifier,
                            'target': entry.get('target') or state['target'],
                            'arguments': entry.get('arguments', {})})
            known.add(identifier)
    results.extend(r for r in current if not r.get('execution_id') or r['execution_id'] not in known)
    return results



def _add_dns(data, item):
    """DoH answers carry their own type; socket fallback answers do not."""
    for record in item.get('records', []):
        kind = (DNS_TYPES.get(record['type'], f"TYPE{record['type']}") if 'type' in record
                else item.get('rtype', 'unknown'))
        value = record.get('data', '')
        data.dns.setdefault(kind, []).append(value)
        if kind not in ('A', 'AAAA') or not isinstance(value, str):
            continue
        try:
            address = ip_address(value)
        except ValueError:
            continue
        expected_version = 4 if kind == 'A' else 6
        if address.version == expected_version:
            data.ips.append(str(address))


def build_session_report(state, level):
    builder = ReportBuilder(state['target'], level, f"LangGraph 会话 {state.get('session_id', '')} · L{level} 受控采集")
    data = builder.data
    results = _observations(state)
    for raw in results:
        result = ToolResult.model_validate(raw)
        name, item = result.name, result.data
        host = item.get('host') or item.get('target') or raw.get('target') or state['target']
        data.raw_refs.extend(result.evidence)
        if result.source_hash:
            data.raw_refs.append(f'{name} SHA256: {result.source_hash}')
        if result.degraded:
            data.degraded.append(f'{name} {host}: 降级结果，confidence={result.confidence}')
        if not result.success:
            data.notes.append(f'{name} {host}: 失败/拦截 — {result.error}')
            continue
        if name == 'dns_query':
            _add_dns(data, item)
        elif name == 'subdomain_enum':
            data.subdomains.extend(item.get('subdomains', []))
            for alive in item.get('alive', []):
                if isinstance(alive, dict):
                    data.alive_hosts.append(alive['host'])
                    data.ips.extend(alive.get('ips', []))
                else:
                    data.alive_hosts.append(alive)
        elif name in ('fingerprint', 'deep_fingerprint') or (name == 'httpx_probe' and 'tech' in item):
            # Independent cards must survive the builder's same-host replacement rule.
            if any(card.get('host') == host and card != item for card in data.tech_cards):
                data.doubts.append(f'{host}: 多次指纹观测有差异；保留全部卡片，待复核')
            data.tech_cards.append(dict(item, host=host))
        elif name in ('nmap_scan', 'builtin_port_scan'):
            previous = data.port_map.get(host, [])
            builder.add_port_scan(host, result)
            data.port_map[host] = sorted(set(previous + data.port_map.get(host, [])))
        elif name == 'dir_enum':
            builder.add_dir_enum(host, result)
        elif name == 'script_probe':
            builder.add_script_probe(host, result)
        elif name == 'api_recon':
            data.api_endpoints.extend(item.get('endpoints', []))
            data.frontend_routes.extend(item.get('frontend_routes', []))
            data.doubts.extend(f'{name}: {note}' for note in item.get('limitations', []))
        elif name == 'takeover_check':
            data.doubts.append(f'{host}: 接管候选（需人工复核） {json.dumps(item, ensure_ascii=False)}')
        elif name in WORKSPACE_TOOLS:
            pass  # Current records are loaded once from the final verified snapshot.
        else:
            data.notes.append(f'{name} {host}: {json.dumps(item, ensure_ascii=False)}')
    apply_tool_report(data, results, state.get('session_id', ''))
    data.api_endpoints = list({json.dumps(e, sort_keys=True, ensure_ascii=False): e for e in data.api_endpoints}.values())
    data.frontend_routes = list(dict.fromkeys(data.frontend_routes))
    data.subdomains = sorted(set(data.subdomains))
    data.alive_hosts = sorted(set(data.alive_hosts))
    data.ips = sorted(set(data.ips))
    data.raw_refs = list(dict.fromkeys(data.raw_refs))
    data.doubts.extend('冲突观测（保留原始证据）: ' + json.dumps(c, ensure_ascii=False)
                       for c in state.get('conflicts', []))
    for event in state.get('events', []):
        data.notes.append('会话事件: ' + json.dumps(event, ensure_ascii=False))
    uncertain = [e for e in state.get('executions', []) if e.get('status') != 'completed' or (e.get('result') or {}).get('outcome_unknown')]
    for entry in uncertain:
        data.doubts.append('uncertain/未完成执行，未自动重试: ' + json.dumps(entry, ensure_ascii=False))
    unknown = state.get('cost_unknown_calls', 0)
    data.notes.append(f"模型 tokens={state.get('used_tokens', 0)}; 已知费用 USD {state.get('used_cost', 0):.6f}" +
                      (f'; 费用未知 {unknown} 次，无法证明总费用精确上限' if unknown else ''))
    data.notes.append(f"任务 {state.get('task_id','')} · 当前上下文约 {state.get('context_tokens',0)}/{state.get('context_capacity',0)} tokens · "
        f"压缩 {state.get('context_compactions',0)} 次 · "
        f"会话累计 {state.get('session_used_tokens',state.get('used_tokens',0))} tokens / USD {state.get('session_used_cost',state.get('used_cost',0)):.6f} · "
        f"用量估算 {state.get('usage_estimated_calls',0)} 次")
    for result in results:
        for artifact in result.get('artifacts',[]):
            data.raw_refs.append(str(artifact.get('path','')))
    if state.get('answer'):
        data.llm_analysis = '模型分析（未验证，不能视为已确认发现）:\n\n' + state['answer']
    marks = []
    if state.get('status') != 'completed' or uncertain:
        marks.append(INCOMPLETE_WATERMARK)
    if data.degraded:
        marks.append(DEGRADED_WATERMARK)
    metrics = TaskMetrics(tool_calls=len(results), tool_success=sum(r['success'] for r in results),
        model_calls=state.get('decisions', 0), scan_level_reached=level,
        contradiction_count=len(state.get('conflicts', [])), uncertainty_count=len(data.doubts),
        total_cost_usd=state.get('used_cost', 0),
        extra={'used_tokens': state.get('used_tokens', 0), 'cost_unknown_calls': unknown,
            'task_id':state.get('task_id',''),'session_used_tokens':state.get('session_used_tokens',0),
            'session_used_cost':state.get('session_used_cost',0),
            **{key:state.get(key,0) for key in ('context_tokens','context_capacity','context_trigger_tokens',
                'context_before_tokens','context_saved_tokens','context_compactions','context_compressed',
                'context_limited','context_estimated')},
            'max_cost':state.get('max_cost',0),'usage_estimated_calls':state.get('usage_estimated_calls',0)})
    return data, metrics, marks, results


def save_session_report(state, level=0, output_format='markdown', out_dir=None):
    if output_format not in ('markdown', 'json', 'csv'):
        raise ValueError('Unsupported report format')
    data, metrics, marks, results = build_session_report(state, level)
    paths = save_report(data, metrics, marks, out_dir, filename_suffix=uuid4().hex[:12])
    payload = json.loads(paths['json'].read_text(encoding='utf-8'))
    payload['session'] = state
    payload['observations'] = results
    paths['json'].write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    with paths['markdown'].open('a', encoding='utf-8') as handle:
        handle.write('\n\n## 完整工具证据（非可信原始数据）\n\n')
        for result in results:
            handle.write(f"### {result['name']} · {result.get('execution_id', '')}\n\n")
            handle.write('```json\n' + json.dumps(result, ensure_ascii=False, indent=2).replace('```', '\\u0060\\u0060\\u0060') + '\n```\n\n')
    paths['selected'] = paths[output_format]
    return paths
