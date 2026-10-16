"""Optional scanner profiles with code-owned argv and bounded evidence.

No scanner accepts operator or model supplied flags. New binary versions must
advertise every required safety flag before any target operation is started.
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from tools.base import BaseTool, ToolResult

KINDS = Literal['subfinder', 'katana', 'ffuf', 'naabu', 'nuclei']
NAMES = {'subfinder':'subfinder_enum', 'katana':'katana_crawl', 'ffuf':'ffuf_enum', 'naabu':'naabu_scan', 'nuclei':'nuclei_scan'}
REQUIRED_FLAGS = {
    'subfinder': ['-d', '-s', '-rl', '-rls', '-t', '-silent', '-duc', '-timeout', '-max-time'],
    'katana': ['-u', '-dr', '-fs', '-cs', '-d', '-ct', '-mdp', '-c', '-p', '-delay', '-retry', '-j', '-duc'],
    'ffuf': ['-u', '-w', '-t', '-p', '-maxtime', '-timeout', '-json', '-noninteractive'],
    'naabu': ['-host', '-s', '-p', '-Pn', '-rate', '-c', '-retries', '-j', '-duc'],
    'nuclei': ['-u', '-t', '-dr', '-ni', '-duc', '-c', '-bs', '-rlm', '-retries', '-j', '-omit-raw'],
}


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: KINDS
    executable: str = ''
    enabled: bool = False
    timeout_seconds: float = Field(60, ge=1, le=120)
    max_output_bytes: int = Field(100000, ge=128, le=262144)
    templates: list[str] = Field(default_factory=list, max_length=20)

    @field_validator('templates')
    @classmethod
    def local_templates(cls, values):
        if any('://' in p or p.startswith(('\\\\', '//')) or Path(p).suffix.lower() not in ('.yaml','.yml') for p in values):
            raise ValueError('templates must be local YAML file paths')
        return values

    @model_validator(mode='after')
    def template_kind(self):
        if self.templates and self.kind != 'nuclei':
            raise ValueError('templates are available only for nuclei')
        return self


class ScannerParams(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=2048)
    paths: list[str] = Field(default_factory=lambda:['api','robots.txt'], min_length=1, max_length=80)
    ports: list[int] = Field(default_factory=lambda:[80,443], min_length=1, max_length=20)

    @field_validator('paths')
    @classmethod
    def literal_paths(cls, values):
        if any(not re.fullmatch(r'[A-Za-z0-9_./-]{1,200}', p) or p.startswith('/') or '..' in p for p in values):
            raise ValueError('paths must be bounded literal relative paths')
        return list(dict.fromkeys(values))

    @field_validator('ports')
    @classmethod
    def tcp_ports(cls, values):
        if any(p < 1 or p > 65535 for p in values):
            raise ValueError('TCP ports must be 1..65535')
        return list(dict.fromkeys(values))


async def _process(*args, **kwargs):
    # Lazy import avoids Settings -> config model -> adapter import cycles.
    from tools.adapters.custom import _bounded_process
    return await _bounded_process(*args, **kwargs)


def checked_target(target, settings):
    from security.stealth import allowed_target
    parsed = urlsplit(target if '://' in target else 'https://' + target)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or any(c in target for c in '\r\n\x00\\'):
        raise ValueError('invalid HTTP target')
    host = parsed.hostname.lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9.:-]+', host) or host.startswith('-'):
        raise ValueError('invalid target host')
    _ = parsed.port
    if not allowed_target(target, settings)[0]:
        raise ValueError('target rejected by scope policy')
    return host, parsed.geturl()


def in_scope(url, target, settings, *, exact=False):
    from security.stealth import allowed_target, is_in_scope, normalize_host
    try:
        checked_target(url, settings)
        return allowed_target(url, settings)[0] and is_in_scope(url, target) and (not exact or normalize_host(url).lower()==normalize_host(target).lower())
    except (ValueError, TypeError):
        return False


def evidence_result(tool, target, payload, *, success=True, code=0, error='', degraded=False):
    from tools.runtime.evidence_store import canonical_json, evidence_store_for, MAX_EVIDENCE_BYTES
    # The process cap applies to raw bytes; this cap covers JSON escaping and
    # duplicate normalized observations in the complete immutable envelope.
    if len(canonical_json(payload)) > MAX_EVIDENCE_BYTES:
        payload = {**payload, 'stdout':'', 'stderr':'', 'result':{}, 'truncated':True}
        degraded = True
    store=evidence_store_for(tool.settings)
    evidence_id=store.put(target,tool.name,payload)
    digest=store.get(evidence_id)['sha256']
    return ToolResult(name=tool.name, success=success, exit_code=code,
        stdout=payload.get('stdout',''),stderr=payload.get('stderr',''),
        data={**payload,'evidence_id':evidence_id},evidence=['local:'+evidence_id],
        source_hash=digest,degraded=degraded,error=error,
        status='timeout' if code==124 else ('success' if success else 'failure'))


def validate_nuclei_template(path):
    """Allow a small structural subset: one GET/HEAD, one anchored path.

    A single request per template makes the inter-process delay a true request
    interval rather than a rate-limit bucket that could permit a burst.
    """
    import yaml
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32768:
        raise ValueError('template must be a bounded local regular file')
    doc=yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(doc,dict) or set(doc)-{'id','info','http'} or not isinstance(doc.get('id'),str):
        raise ValueError('unsupported template structure')
    requests=doc.get('http')
    if not isinstance(requests,list) or len(requests)!=1 or not isinstance(requests[0],dict):
        raise ValueError('one bounded HTTP request required')
    req=requests[0]
    if set(req)-{'method','path','matchers','matchers-condition'} or req.get('method','GET') not in ('GET','HEAD'):
        raise ValueError('only simple GET/HEAD HTTP templates supported')
    paths=req.get('path')
    if not isinstance(paths,list) or len(paths)!=1 or not isinstance(paths[0],str) or not re.fullmatch(r'\{\{(?:BaseURL|RootURL)\}\}/[A-Za-z0-9_./?=&%-]{0,200}',paths[0]):
        raise ValueError('only literal BaseURL/RootURL anchored path supported')
    if '..' in paths[0] or paths[0].split('}}',1)[1].startswith('//'):
        raise ValueError('unsafe path')
    matchers=req.get('matchers',[])
    if not isinstance(matchers,list) or len(matchers)>10:
        raise ValueError('invalid matchers')
    for matcher in matchers:
        if not isinstance(matcher,dict) or set(matcher)-{'type','status','words','regex','part','condition','negative','case-insensitive'} or matcher.get('type') not in ('status','word','regex'):
            raise ValueError('unsupported matcher')
    # No DSL/interpolation anywhere outside the one checked path.
    stripped=json.dumps({**doc,'http':[{k:v for k,v in req.items() if k!='path'}]})
    if '{{' in stripped or '}}' in stripped:
        raise ValueError('dynamic template interpolation forbidden')
    return doc


class ScannerTool(BaseTool):
    deferred=True
    cacheable=False
    params_model=ScannerParams

    def __init__(self, config, settings, lock):
        self.config=config;self.settings=settings;self._lock=lock
        self.name=NAMES[config.kind];self.min_level=0 if config.kind=='subfinder' else 2
        self.risk_level='低' if self.min_level==0 else '高'
        self.description='Controlled optional '+config.kind+' profile; explicit bounded scope and immutable evidence'
        if config.kind=='subfinder':
            self.description+='; passive hackertarget source only, incomplete enumeration'

    def _normalized(self, stdout, target, params):
        kind=self.config.kind
        if kind=='subfinder':
            return {'subdomains':[s.strip() for s in stdout.splitlines() if in_scope(s.strip(),target,self.settings)],
                'candidate':True,'sources':['hackertarget'],'complete':False,
                'limitations':['One bounded HTTP passive provider; enumeration is incomplete.']}
        rows=[]
        for line in stdout.splitlines():
            try:
                item=json.loads(line)
                if kind=='ffuf' and isinstance(item,dict):
                    # -json emits individual Result objects on stdout. The
                    # results envelope belongs to -of json files; accept both.
                    if isinstance(item.get('results'),list):rows.extend(item['results'])
                    elif isinstance(item.get('url'),str):rows.append(item)
                elif isinstance(item,dict):rows.append(item)
            except (ValueError,TypeError,AttributeError):continue
        if kind=='naabu':
            return {'open_ports':sorted({r['port'] for r in rows if r.get('port') in params.ports and in_scope(r.get('host',''),target,self.settings,exact=True)}),'scan_type':'TCP Connect'}
        observations=[]
        for row in rows[:1000]:
            if not isinstance(row,dict):continue
            request=row.get('request') or {};response=row.get('response') or {}
            if not isinstance(request,dict):request={}
            if not isinstance(response,dict):response={}
            url=request.get('endpoint') or row.get('url') or row.get('matched-at') or row.get('host')
            if not url or not in_scope(url,target,self.settings,exact=True):continue
            status=response.get('status_code') or row.get('status')
            observations.append({'url':url,'method':request.get('method','GET'),'status':status,'candidate':not isinstance(status,int), **({'template_id':row.get('template-id'),'unverified':True} if kind=='nuclei' else {})})
        return {'endpoints':[r['url'] for r in observations],'requests':observations,**({'findings':observations} if kind=='nuclei' else {})}

    async def run(self, params):
        try:
            host,url=checked_target(params.target,self.settings)
            binary=shutil.which(self.config.executable or self.config.kind)
            if not binary:return ToolResult.err(self.name,'scanner dependency unavailable: '+self.config.kind)
            kind=self.config.kind
            delay=max(1,math.ceil(max(getattr(self.settings,'REQUEST_DELAY_RANGE',(3,10)))))
            async with self._lock:
                code,help_text,_,truncated=await _process([binary,'-h'],min(10,self.config.timeout_seconds),65536)
                advertised={word.rstrip(',') for word in help_text.split()}
                if code or truncated or any(flag not in advertised for flag in REQUIRED_FLAGS[kind]):
                    return ToolResult.err(self.name,'scanner required safety flags unsupported')
                with tempfile.TemporaryDirectory(prefix='recon-scanner-') as folder:
                    work=Path(folder)
                    # Prevent implicit user rc files from enabling proxying, replay,
                    # headless execution, remote templates, or aggressive options.
                    env={**os.environ,'HOME':folder,'USERPROFILE':folder,'XDG_CONFIG_HOME':folder,'APPDATA':folder}
                    for key in list(env):
                        if key.lower() in ('http_proxy','https_proxy','all_proxy','subfinder_config','subfinder_provider_config'):env.pop(key)
                    commands=[]
                    if kind=='subfinder':
                        passive_delay=max(1,math.ceil(max(getattr(self.settings,'L0_DELAY_RANGE',(1,2.5)))))
                        if passive_delay>3600:raise ValueError('passive delay exceeds supported provider rate period')
                        period='m' if passive_delay<=60 else 'h'
                        # Many upstream sources run concurrently, and crtsh can
                        # bypass HTTP limits through SQL. One fixed HTTP-only
                        # source keeps the profile passive and its rate truthful.
                        commands=[[binary,'-d',host,'-s','hackertarget','-rl','1','-rls','hackertarget=1/'+period,
                            '-t','1','-silent','-duc','-timeout',str(min(10,math.ceil(self.config.timeout_seconds))),
                            '-max-time',str(math.ceil(self.config.timeout_seconds/60))]]
                    elif kind=='katana':commands=[[binary,'-u',url,'-dr','-fs','fqdn','-cs',r'^https?://'+re.escape(urlsplit(url).netloc)+r'(?:/|$)','-d','2','-ct',str(int(self.config.timeout_seconds))+'s','-mdp','80','-c','1','-p','1','-delay',str(delay),'-retry','0','-j','-duc']]
                    elif kind=='ffuf':
                        wordlist=work/'paths.txt';wordlist.write_text('\n'.join(params.paths),encoding='utf-8')
                        commands=[[binary,'-u',url.rstrip('/')+'/FUZZ','-w',str(wordlist),'-t','1','-p',str(delay),'-maxtime',str(int(self.config.timeout_seconds)),'-timeout','10','-json','-noninteractive']]
                    elif kind=='naabu':
                        # Naabu counts complete passes as retries: zero silently
                        # restores its aggressive default, while one is one pass.
                        commands=[[binary,'-host',host,'-s','c','-p',str(port),'-Pn','-rate','1','-c','1','-retries','1','-j','-duc'] for port in params.ports]
                    else:
                        if not self.config.templates:raise ValueError('explicit local nuclei templates required')
                        import yaml
                        for index,path in enumerate(self.config.templates):
                            snapshot=work/(str(index)+'.yaml');snapshot.write_text(yaml.safe_dump(validate_nuclei_template(path)),encoding='utf-8')
                            commands.append([binary,'-u',url,'-t',str(snapshot),'-dr','-ni','-duc','-c','1','-bs','1','-rlm','1','-retries','0','-j','-omit-raw'])
                    async def execute():
                        output=[];errors=[];remaining=self.config.max_output_bytes;any_truncated=False
                        for index,argv in enumerate(commands):
                            if kind=='subfinder':await asyncio.sleep(passive_delay)
                            elif index:await asyncio.sleep(delay)
                            result=await _process(argv,self.config.timeout_seconds,remaining,env=env)
                            code,out,err,cut=result;output.append(out);errors.append(err)
                            remaining-=len(out.encode())+len(err.encode());any_truncated|=cut
                            if code or remaining<=0:break
                        return code,'\n'.join(output),'\n'.join(errors),any_truncated
                    try:
                        code,out,err,cut=await asyncio.wait_for(execute(),self.config.timeout_seconds)
                    except asyncio.TimeoutError:
                        code,out,err,cut=124,'','',True
            payload={'target':params.target,'kind':kind,'stdout':out,'stderr':err,'exit_code':code,'truncated':cut,'result':self._normalized(out,params.target,params)}
            return evidence_result(self,params.target,payload,success=code==0,code=code,error='scanner timeout' if code==124 else ('scanner failed' if code else ''),degraded=cut)
        except asyncio.CancelledError:raise
        except ValueError as exc:return ToolResult.err(self.name,'scanner configuration rejected: '+str(exc))
        except Exception:return ToolResult.err(self.name,'scanner execution failed')


def build_scanner_tools(settings):
    configs=getattr(getattr(settings,'extension_tools',None),'scanners',[])
    tools=[];seen=set();lock=asyncio.Lock()
    for raw in configs:
        config=raw if isinstance(raw,ScannerConfig) else ScannerConfig.model_validate(raw)
        if not config.enabled:continue
        if config.kind in seen:raise ValueError('duplicate scanner kind')
        seen.add(config.kind);tools.append(ScannerTool(config,settings,lock))
    return tools
