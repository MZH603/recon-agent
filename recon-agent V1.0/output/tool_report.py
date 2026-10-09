"""Convert optional observations and the final workspace snapshot to reports."""
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from security.stealth import normalize_host
from tools.runtime.evidence_store import EvidenceStore

WORKSPACE_TOOLS = {'recon_note', 'recon_coverage', 'recon_threat_model', 'recon_finding', 'workspace_snapshot'}


def _endpoints(item, source):
    requests = item.get('requests', [])
    if not requests:
        requests = item.get('endpoints', [])
    result = []
    for sample in requests:
        if isinstance(sample, str):
            sample = {'url': sample, 'candidate': True}
        if not isinstance(sample, dict):
            continue
        if 'path' in sample and not sample.get('url'):
            result.append(sample)
            continue
        parts = urlsplit(sample.get('url') or '')
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            continue
        method = sample.get('method')
        observed = sample.get('observed') is True or isinstance(sample.get('status'), int)
        result.append({'method': method if method in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS') else None,
            'path': parts.path or '/', 'params': sorted({name for name, _ in parse_qsl(parts.query)} |
                {name for name in sample.get('params', []) if isinstance(name, str)}),
            'source': source, 'observed': observed and not sample.get('candidate') and sample.get('observed') is not False})
    return result


def apply_tool_report(data, results, session_id=''):
    snapshots = {}
    for result in results:
        if not result.get('success'):
            continue
        name = result['name']
        envelope = result.get('data') or {}
        item = envelope.get('result') if isinstance(envelope.get('result'), dict) else envelope
        host = item.get('host') or envelope.get('target') or result.get('target') or data.target
        source = 'evidence:' + envelope['evidence_id'] if envelope.get('evidence_id') else name
        if name == 'subfinder_enum':
            data.subdomains.extend(item.get('subdomains', []))
        elif name == 'naabu_scan':
            data.port_map[host] = sorted(set(data.port_map.get(host, []) + item.get('open_ports', [])))
        elif name in ('katana_crawl', 'ffuf_enum', 'list_requests', 'view_request', 'list_sitemap'):
            data.api_endpoints.extend(_endpoints(item, source))
            if item.get('has_more') or item.get('complete') is False:
                data.doubts.append(f'{name}: 有限请求页或推导结果，未证明完整覆盖')
        elif name == 'nuclei_scan':
            for finding in item.get('findings', []):
                data.findings.append({**finding, 'title': finding.get('title') or finding.get('template_id') or 'Template match',
                    'severity': finding.get('severity', 'info'), 'status': 'candidate', 'source': source,
                    'verification_note': '模板命中，仅线索，待复核'})
        elif name in WORKSPACE_TOOLS:
            key = normalize_host(host).lower()
            try:
                artifact = next(a for a in result.get('artifacts', []) if a.get('kind') == 'workspace_snapshot')
                identifier = artifact['evidence_id']
                path = Path(artifact['path'])
                if path.name != identifier + '.json':
                    raise ValueError('invalid snapshot filename')
                record = EvidenceStore(path.parent).get(identifier, target=host)
                payload = record['payload']
                if record['kind'] != 'workspace_snapshot' or record['sha256'] != result.get('source_hash'):
                    raise ValueError('invalid snapshot provenance')
                if session_id and payload.get('session_id') != session_id:
                    data.doubts.append(f'{name}: 已忽略其他会话的记录快照')
                    continue
                snapshots[key] = payload['workspace']
            except (OSError, ValueError, KeyError, StopIteration, TypeError):
                # An unverifiable latest snapshot cannot fall back to stale findings.
                snapshots.pop(key, None)
                data.doubts.append(f'{name}: 当前记录快照不可验证；历史记录不作为当前发现')
    for workspace in snapshots.values():
        data.workspace_notes.extend(workspace.get('notes', []))
        data.coverage.extend(workspace.get('coverage', []))
        data.threat_models.extend(workspace.get('threat_models', []))
        data.findings.extend(workspace.get('findings', []))
