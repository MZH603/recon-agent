import asyncio
import json
from types import SimpleNamespace
import pytest
from pydantic import ValidationError


def module():
    from tools.adapters import scanners
    return scanners


def settings(tmp_path, configs):
    return SimpleNamespace(extension_tools=SimpleNamespace(scanners=configs), TOOL_EVIDENCE_DIR=str(tmp_path),REQUEST_DELAY_RANGE=(3,10),MAX_CONCURRENCY=1,LAB_MODE=False,PROTECTED_TLDS=('.gov','.mil'))


def test_defaults_and_closed_configuration(tmp_path):
    m=module()
    assert not m.ScannerConfig(kind='katana').enabled
    assert m.build_scanner_tools(settings(tmp_path,[{'kind':'katana'}]))==[]
    for bad in ({'kind':'shell'},{'kind':'katana','arguments':['-ns']},{'kind':'nuclei','templates':['https://evil/t.yaml']},{'kind':'ffuf','timeout_seconds':121}):
        with pytest.raises(ValidationError): m.ScannerConfig(**bad)
    for bad in ({'args':['-ns']},{'ports':list(range(1,22))},{'paths':['https://evil/']}):
        with pytest.raises(ValidationError): m.ScannerParams(target='example.com',**bad)


@pytest.mark.parametrize('kind,name', [('katana','katana_crawl'),('ffuf','ffuf_enum'),('naabu','naabu_scan'),('subfinder','subfinder_enum')])
def test_controlled_argv_and_evidence(tmp_path,monkeypatch,kind,name):
    m=module(); calls=[]
    async def fake(argv,timeout,max_bytes,**kwargs):
        calls.append(argv)
        if '-h' in argv: return 0,' '.join(m.REQUIRED_FLAGS[kind]),'',False
        if kind=='subfinder': out='api.example.com\nforeign.test\n'
        elif kind=='naabu': out=json.dumps({'host':'example.com','port':443})+'\n'+json.dumps({'host':'foreign.test','port':99})
        elif kind=='katana': out=json.dumps({'request':{'endpoint':'https://example.com/api','method':'GET'},'response':{'status_code':200}})+'\n'+json.dumps({'url':'https://foreign.test/'})
        else: out=json.dumps({'results':[{'url':'https://example.com/api','status':200},{'url':'https://foreign.test/','status':200}]})
        return 0,out,'',False
    monkeypatch.setattr(m,'_process',fake)
    monkeypatch.setattr(m.shutil,'which',lambda executable:executable)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':kind,'enabled':True}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com',paths=['api'],ports=[443])))
    assert result.success, result.error
    assert tool.name==name and tool.deferred and not tool.cacheable
    assert tool.min_level==(0 if kind=='subfinder' else 2)
    assert result.source_hash and result.evidence
    assert 'foreign.test' not in json.dumps(result.data['result'])
    argv=calls[-1]
    if kind=='katana':
        assert '-dr' in argv and argv[argv.index('-fs')+1]=='fqdn'
        assert argv[argv.index('-mdp')+1]=='80' and argv[argv.index('-retry')+1]=='0'
        assert argv[argv.index('-delay')+1]=='10'
    if kind=='ffuf':
        assert '-r' not in argv and argv[argv.index('-t')+1]=='1'
        assert argv[argv.index('-p')+1]=='10'
    if kind=='naabu':
        assert argv[argv.index('-s')+1]=='c' and '-Pn' in argv
        assert argv[argv.index('-p')+1]=='443'
        assert argv[argv.index('-rate')+1]=='1'


def test_naabu_has_one_pass_per_port(tmp_path,monkeypatch):
    m=module();calls=[];delays=[]
    async def fake(argv,*args,**kwargs):
        calls.append(argv)
        return (0,' '.join(m.REQUIRED_FLAGS['naabu']),'',False) if '-h' in argv else (0,'','',False)
    async def sleep(delay):delays.append(delay)
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x);monkeypatch.setattr(m.asyncio,'sleep',sleep)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'naabu','enabled':True}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com',ports=[80,443])))
    assert result.success and delays==[10]
    assert all(argv[argv.index('-retries')+1]=='1' for argv in calls[1:])


def test_process_cancel_propagates_and_missing_dependency(tmp_path,monkeypatch):
    m=module();tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'katana','enabled':True}]))[0]
    monkeypatch.setattr(m.shutil,'which',lambda x:None)
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert not result.success and 'dependency' in result.error
    monkeypatch.setattr(m.shutil,'which',lambda x:x)
    async def cancel(*args,**kwargs):raise asyncio.CancelledError
    monkeypatch.setattr(m,'_process',cancel)
    with pytest.raises(asyncio.CancelledError):asyncio.run(tool.run(m.ScannerParams(target='example.com')))


def test_unsupported_flags_fail_before_scan(tmp_path,monkeypatch):
    m=module();calls=[]
    async def fake(argv,*args,**kwargs): calls.append(argv);return 0,'old binary','',False
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'katana','enabled':True}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert not result.success and 'flags' in result.error
    assert len(calls)==1


def test_real_cli_help_alias_commas_are_accepted(tmp_path,monkeypatch):
    m=module()
    async def fake(argv,*args,**kwargs):
        if '-h' in argv:return 0,'\n'.join('   '+flag+', --long-alias    documented safety flag' for flag in m.REQUIRED_FLAGS['katana']),'',False
        return 0,'','',False
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'katana','enabled':True}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert result.success,result.error


def test_ffuf_real_jsonl_hit_records_are_normalized(tmp_path,monkeypatch):
    m=module()
    async def fake(argv,*args,**kwargs):
        if '-h' in argv:return 0,' '.join(m.REQUIRED_FLAGS['ffuf']),'',False
        return 0,'\n'.join(json.dumps(row) for row in [
            {'input':{'FUZZ':'YXBp'},'position':1,'status':200,'length':123,'words':4,'lines':2,'url':'https://example.com/api','redirectlocation':'','duration':3000000},
            {'input':{'FUZZ':'cm9ib3RzLnR4dA=='},'position':2,'status':301,'length':0,'url':'https://example.com/robots.txt','redirectlocation':'https://foreign.test/'},
            {'status':200,'url':'https://foreign.test/api'}]),'',False
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'ffuf','enabled':True}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert result.success
    assert result.data['result']['requests']==[
        {'url':'https://example.com/api','method':'GET','status':200,'candidate':False},
        {'url':'https://example.com/robots.txt','method':'GET','status':301,'candidate':False}]


def test_subfinder_single_passive_provider_policy(tmp_path,monkeypatch):
    m=module();calls=[];delays=[]
    async def fake(argv,*args,**kwargs):
        calls.append((argv,kwargs))
        if '-h' in argv:return 0,' '.join(m.REQUIRED_FLAGS['subfinder']),'',False
        return 0,'api.example.com\n','',False
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x)
    async def sleep(delay):delays.append(delay)
    monkeypatch.setattr(m.asyncio,'sleep',sleep)
    monkeypatch.setenv('SUBFINDER_CONFIG','foreign-user-config.yaml')
    config=settings(tmp_path,[{'kind':'subfinder','enabled':True}]);config.L0_DELAY_RANGE=(1,2.5)
    tool=m.build_scanner_tools(config)[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert result.success
    argv,kwargs=calls[-1]
    assert argv[argv.index('-s')+1]=='hackertarget'
    assert argv[argv.index('-rl')+1]=='1' and argv[argv.index('-rls')+1]=='hackertarget=1/m'
    assert argv[argv.index('-t')+1]=='1' and '-active' not in argv and '-nW' not in argv
    assert 'SUBFINDER_CONFIG' not in kwargs['env']
    assert result.data['result']['sources']==['hackertarget'] and result.data['result']['complete'] is False
    assert delays==[3] and 'hackertarget' in tool.description and 'incomplete' in tool.description


def test_subfinder_missing_rate_flag_fails_closed(tmp_path,monkeypatch):
    m=module();calls=[]
    async def fake(argv,*args,**kwargs):
        calls.append(argv)
        return 0,' '.join(flag for flag in m.REQUIRED_FLAGS['subfinder'] if flag!='-rls'),'',False
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'subfinder','enabled':True}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert not result.success and 'flags' in result.error and len(calls)==1


@pytest.mark.parametrize('body', ["id: x\nhttp:\n- method: POST\n  path: ['{{BaseURL}}/']", "id: x\nhttp:\n- method: GET\n  path: ['https://evil/']", "id: x\nhttp:\n- method: GET\n  path: ['{{BaseURL}}/{{randstr}}']", "id: x\nhttp:\n- raw: ['GET / HTTP/1.1']", "id: x\nhttp:\n- method: GET\n  path: ['{{BaseURL}}/']\n  redirects: true", "id: x\ncode: []\nhttp: []"])
def test_nuclei_rejects_unsafe_templates(tmp_path,body):
    m=module();p=tmp_path/'t.yaml';p.write_text(body)
    with pytest.raises(ValueError):m.validate_nuclei_template(p)


def test_nuclei_safe_template_and_timeout(tmp_path,monkeypatch):
    m=module();p=tmp_path/'t.yaml';p.write_text("id: x\ninfo: {name: x, author: x, severity: info}\nhttp:\n- method: GET\n  path: ['{{BaseURL}}/api']\n  matchers:\n  - type: status\n    status: [200]\n")
    assert m.validate_nuclei_template(p)
    calls=[]
    async def fake(argv,*args,**kwargs):
        calls.append(argv)
        if '-h' in argv:return 0,' '.join(m.REQUIRED_FLAGS['nuclei']),'',False
        return 124,'partial','',True
    monkeypatch.setattr(m,'_process',fake);monkeypatch.setattr(m.shutil,'which',lambda x:x)
    tool=m.build_scanner_tools(settings(tmp_path,[{'kind':'nuclei','enabled':True,'templates':[str(p)]}]))[0]
    result=asyncio.run(tool.run(m.ScannerParams(target='example.com')))
    assert result.status=='timeout' and result.degraded and result.data['truncated']
    assert '-ni' in calls[-1] and '-dr' in calls[-1] and '-duc' in calls[-1]
