import json

import importlib.util


def test_session_report_module_exists():
    assert importlib.util.find_spec('output.session_report') is not None


def result(name, data, **extra):
    return dict(name=name, success=True, data=data, stdout='full output', stderr='diagnostic',
                evidence=['fixture://evidence'], source_hash='abc', confidence=1, degraded=False,
                error='', exit_code=0, target='example.com', arguments={'target': 'example.com'},
                **extra)


def test_session_report_preserves_complete_state_and_conflicting_cards(tmp_path):
    from output import session_report
    state = dict(target='example.com', session_id='fixture', status='paused', pending={'kind': 'model_unavailable'},
                 used_tokens=123, used_cost=0.2, cost_unknown_calls=1,
                 results=[result('dns_query', {'rtype': 'A', 'records': [{'data': '192.0.2.1'}]}),
                          result('fingerprint', {'host': 'example.com', 'tech': {'server': {'name': 'nginx'}}}),
                          result('deep_fingerprint', {'host': 'example.com', 'tech': {'server': {'name': 'apache'}}})],
                 conflicts=[{'old': 'nginx', 'new': 'apache'}], events=[{'kind': 'model_unavailable'}],
                 executions=[{'status': 'uncertain', 'execution_id': 'lost'}], answer='LLM opinion')
    paths = session_report.save_session_report(state, 0, 'json', tmp_path)
    payload = json.loads(paths['json'].read_text(encoding='utf-8'))
    assert payload['session'] == state
    assert payload['report']['ips'] == ['192.0.2.1']
    assert len(payload['report']['tech_cards']) == 2
    text = paths['markdown'].read_text(encoding='utf-8')
    assert '[INCOMPLETE]' in text and '未验证' in text and 'uncertain' in text
    assert 'fixture://evidence' in text and '费用未知' in text
    assert paths['selected'] == paths['json']
    assert session_report.save_session_report(state, 0, 'csv', tmp_path)['json'] != paths['json']


def test_all_tool_shapes_are_visible_and_failures_recorded(tmp_path):
    from output import session_report
    values = [result('subdomain_enum', {'domain': 'example.com', 'subdomains': ['a.example.com'], 'alive': ['a.example.com']}),
              result('httpx_probe', {'target': 'example.com', 'raw': 'external scan text'}),
              result('builtin_port_scan', {'open_ports': [80]}),
              result('dir_enum', {'host': 'example.com', 'found': [{'path': '/admin', 'status': 200}], 'checked': 3}),
              result('script_probe', {'exit_code': 0, 'output': 'script output'}),
              result('system_scan', {'tool': 'nuclei', 'raw_output': 'raw nuclei'}),
              result('takeover_check', {'host': 'a.example.com', 'provider': 'x', 'vulnerable': True, 'note': 'candidate'}),
              result('wayback_urls', {'domain': 'example.com', 'urls': ['https://example.com/old'], 'count': 1}),
              dict(result('nmap_scan', {}), success=False, error='blocked by gate')]
    state = {'target': 'example.com', 'session_id': 'all', 'status': 'completed', 'results': values}
    paths = session_report.save_session_report(state, 1, 'markdown', tmp_path)
    body = paths['markdown'].read_text(encoding='utf-8')
    for expected in ['a.example.com', '/admin', 'external scan text', 'script output', 'raw nuclei', '/old', 'blocked by gate']:
        assert expected in body
    report = json.loads(paths['json'].read_text(encoding='utf-8'))['report']
    assert report['port_map']['example.com'] == [80]
    assert report['risk_paths'][0]['path'] == '/admin'


def test_httpx_fallback_card_is_structured_and_journal_only_result_is_retained(tmp_path):
    from output import session_report
    card=result('httpx_probe', {'host': 'example.com', 'tech': {'middleware': {'name': 'nginx'}}})
    state={'target': 'example.com', 'status': 'paused', 'results': [], 'executions': [
        {'execution_id': 'journal', 'status': 'completed', 'result': card, 'target': 'example.com'}]}
    paths=session_report.save_session_report(state, 0, 'json', tmp_path)
    data=json.loads(paths['json'].read_text(encoding='utf-8'))
    assert data['report']['tech_cards'][0]['tech']['middleware']['name'] == 'nginx'
    assert data['observations'][0]['execution_id'] == 'journal'


def test_real_subdomain_alive_shape_keeps_hosts_and_ips(tmp_path):
    from output import session_report
    state={'target': 'example.com', 'status': 'completed', 'results': [result('subdomain_enum', {
        'domain': 'example.com', 'subdomains': ['a.example.com'],
        'alive': [{'host': 'a.example.com', 'ips': ['192.0.2.2']}], 'sources': {'ct': 1},
        'san': ['a.example.com'], 'recursive': False, 'notes': []})]}
    paths=session_report.save_session_report(state, 0, 'json', tmp_path)
    data=json.loads(paths['json'].read_text(encoding='utf-8'))
    assert data['report']['alive_hosts'] == ['a.example.com']
    assert data['report']['ips'] == ['192.0.2.2']


def test_degraded_and_paused_validation_failures_are_reported(tmp_path):
    from output import session_report
    state={'target': 'example.com', 'status': 'paused',
        'pending': {'kind': 'schema', 'question': 'valid parameters?'},
        'events': [{'kind': 'schema', 'question': 'valid parameters?'}, {'kind': 'budget'}],
        'results': [dict(result('fingerprint', {'host': 'example.com', 'tech': {}}), degraded=True, confidence=0.6)]}
    paths=session_report.save_session_report(state, 0, 'markdown', tmp_path)
    text=paths['markdown'].read_text(encoding='utf-8')
    assert '[降级模式]' in text and '[INCOMPLETE]' in text
    assert 'valid parameters?' in text and 'budget' in text


def test_dns_actual_answer_types_separate_cname_from_a_and_keep_sources(tmp_path):
    import csv
    from output import session_report
    records = [{'name': 'example.com', 'type': 5, 'data': 'example.cdn.test'},
               {'name': 'example.cdn.test', 'type': 1, 'data': '192.0.2.1'}]
    observation = result('dns_query', {'target': 'example.com', 'rtype': 'A', 'records': records})
    state = {'target': 'example.com', 'status': 'completed', 'results': [observation]}
    paths = session_report.save_session_report(state, 0, 'json', tmp_path)
    payload = json.loads(paths['json'].read_text(encoding='utf-8'))
    assert payload['report']['dns'] == {'CNAME': ['example.cdn.test'], 'A': ['192.0.2.1']}
    assert payload['report']['ips'] == ['192.0.2.1']
    assert payload['session']['results'] == payload['observations'] == [observation]
    body = paths['markdown'].read_text(encoding='utf-8')
    ip_line = next(line for line in body.splitlines() if line.startswith('- 解析 IP:'))
    assert 'example.cdn.test' not in ip_line and '192.0.2.1' in ip_line
    assert 'example.cdn.test' in body and 'fixture://evidence' in body and 'abc' in body
    with paths['csv'].open(encoding='utf-8', newline='') as handle:
        ip_rows = [row for row in csv.reader(handle) if row and row[0] == 'ip']
    assert ip_rows == [['ip', '192.0.2.1', '解析记录']]


def test_dns_aaaa_malformed_unknown_and_socket_records_are_not_misclassified(tmp_path):
    import csv
    from output import session_report
    records = [{'type': 5, 'data': 'v6.cdn.test'},
               {'type': 28, 'data': '2001:db8::1'},
               {'type': 28, 'data': '192.0.2.3'},  # Wrong family for AAAA.
               {'type': 1, 'data': '2001:db8::2'},  # Wrong family for A.
               {'type': 1, 'data': 'not-an-address'},
               {'type': 28, 'data': None},
               {'type': 99, 'data': 'opaque unknown record'}]
    doh = result('dns_query', {'rtype': 'AAAA', 'records': records})
    socket = result('dns_query', {'rtype': 'A', 'records': [{'data': '192.0.2.4'},
                                                            {'data': 'fallback.invalid'}]})
    state = {'target': 'example.com', 'status': 'completed', 'results': [doh, socket]}
    paths = session_report.save_session_report(state, 0, 'json', tmp_path)
    payload = json.loads(paths['json'].read_text(encoding='utf-8'))
    dns = payload['report']['dns']
    assert dns['CNAME'] == ['v6.cdn.test']
    assert dns['AAAA'] == ['2001:db8::1', '192.0.2.3', None]
    assert dns['A'] == ['2001:db8::2', 'not-an-address', '192.0.2.4', 'fallback.invalid']
    assert dns['TYPE99'] == ['opaque unknown record']
    assert payload['report']['ips'] == ['192.0.2.4', '2001:db8::1']
    assert payload['observations'] == [doh, socket]
    body = paths['markdown'].read_text(encoding='utf-8')
    ip_line = next(line for line in body.splitlines() if line.startswith('- 解析 IP:'))
    assert 'v6.cdn.test' not in ip_line and 'fallback.invalid' not in ip_line
    assert 'fixture://evidence' in body and 'opaque unknown record' in body
    with paths['csv'].open(encoding='utf-8', newline='') as handle:
        ip_assets = [row[1] for row in csv.reader(handle) if row and row[0] == 'ip']
    assert ip_assets == ['192.0.2.4', '2001:db8::1']
