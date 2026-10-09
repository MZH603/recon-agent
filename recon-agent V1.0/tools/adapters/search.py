"""Fixed Exa/Perplexity services; async bounded I/O, unverified intelligence."""
from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
from typing import Literal
from urllib.parse import quote, quote_plus, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator
from tools.base import BaseTool, ToolResult
from tools.adapters.scanners import checked_target, evidence_result

SERVICES={'exa':'api.exa.ai','perplexity':'api.perplexity.ai'}


class SearchConfig(BaseModel):
    model_config=ConfigDict(extra='forbid')
    enabled: bool=False
    provider: Literal['exa','perplexity']='exa'
    api_key_env: str=Field('',pattern=r'^(?:[A-Za-z_][A-Za-z0-9_]{0,127})?$')
    timeout_seconds: float=Field(30,ge=1,le=120)
    max_output_bytes: int=Field(100000,ge=128,le=262144)


class SearchParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    query: str=Field(min_length=1,max_length=4000)
    num_results: int=Field(5,ge=1,le=10)


class ContentsParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    urls: list[str]=Field(min_length=1,max_length=5)

    @field_validator('urls')
    @classmethod
    def public_urls(cls,values):
        for url in values:
            parts=urlsplit(url)
            if len(url)>2048 or parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password or any(c in url for c in '\r\n\x00\\'):
                raise ValueError('contents requires public HTTP URLs without credentials')
        return values


def redact(value,secret):
    if isinstance(value,str):
        fully_unicode=''.join('\\u%04x'%int.from_bytes(secret.encode('utf-16-be')[i:i+2],'big') for i in range(0,len(secret.encode('utf-16-be')),2))
        variants={secret,json.dumps(secret,ensure_ascii=True)[1:-1],fully_unicode}
        for _ in range(2):
            variants|={json.dumps(variant,ensure_ascii=True)[1:-1] for variant in variants}
        encoded={quote(secret,safe=''),quote_plus(secret,safe=''),''.join('%%%02X'%b for b in secret.encode())}
        for _ in range(3):
            encoded|={quote(variant,safe='') for variant in encoded}
        for variant in sorted(encoded-variants,key=len,reverse=True):
            if variant:value=re.sub(re.escape(variant),'[REDACTED]',value,flags=re.IGNORECASE)
        for variant in sorted(variants,key=len,reverse=True):
            if variant:value=value.replace(variant,'[REDACTED]')
        return value
    if isinstance(value,dict):return {redact(str(k),secret):redact(v,secret) for k,v in value.items()}
    if isinstance(value,list):return [redact(v,secret) for v in value]
    return value


async def _service_post(service,path,payload,headers,timeout,max_bytes):
    """Direct TLS to a fixed service; redirects and env proxies never followed.

    Cancelling closes the actual socket in finally. No executor thread continues
    sending requests after a registry cancellation has finished.
    """
    if service not in SERVICES or path not in ('/search','/contents','/chat/completions'):
        raise ValueError('unsupported search service operation')
    return await bounded_json_post('https://'+SERVICES[service],path,payload,headers,timeout,max_bytes)


async def bounded_json_post(origin,path,payload,headers,timeout,max_bytes):
    """Internal HTTP transport used only by fixed service/query adapters."""
    parts=urlsplit(origin)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('','/'):
        raise ValueError('invalid fixed service origin')
    if path not in ('/search','/contents','/chat/completions','/graphql'):
        raise ValueError('unsupported fixed service path')
    body=json.dumps(payload,ensure_ascii=True).encode()
    if len(body)>32768:raise ValueError('search request size limit')
    host=parts.hostname;port=parts.port or (443 if parts.scheme=='https' else 80)
    writer=None
    async def exchange():
        nonlocal writer
        from tools.adapters.integration_http import _read_body
        tls=parts.scheme=='https'
        reader,writer=await asyncio.open_connection(host,port,ssl=ssl.create_default_context() if tls else None,server_hostname=host if tls else None,limit=65536)
        if any(any(c in str(k)+str(v) for c in '\r\n\x00') for k,v in headers.items()):raise ValueError('invalid credential header')
        request=f'POST {path} HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n'+''.join(f'{k}: {v}\r\n' for k,v in headers.items())+'\r\n'
        writer.write(request.encode('ascii')+body);await writer.drain()
        block=await reader.readuntil(b'\r\n\r\n')
        if len(block)>65536:raise ValueError('service header limit')
        lines=block.decode('iso-8859-1').split('\r\n');status=int(lines[0].split()[1]);response_headers={}
        for line in lines[1:]:
            if line:
                key,value=line.split(':',1);response_headers[key.lower()]=value.strip()
        if not 200<=status<300:raise ValueError('search service rejected request')
        raw,truncated=await _read_body(reader,response_headers,status,'POST',max_bytes)
        if truncated:return {},True
        value=json.loads(raw)
        if not isinstance(value,dict):raise ValueError('invalid service response')
        return value,False
    try:return await asyncio.wait_for(exchange(),timeout)
    finally:
        if writer is not None:
            writer.close()
            try:await asyncio.wait_for(writer.wait_closed(),1)
            except (OSError,asyncio.TimeoutError):pass


class SearchTool(BaseTool):
    remote_execution=True
    deferred=True
    cacheable=False
    min_level=0

    def __init__(self,config,settings,contents=False):
        self.config=config;self.settings=settings;self.contents=contents
        self.name='web_get_contents' if contents else 'web_search'
        self.params_model=ContentsParams if contents else SearchParams
        self.description='Bounded '+config.provider+' public intelligence; third-party content is unverified'

    async def run(self,params):
        try:
            checked_target(params.target,self.settings)
            env=self.config.api_key_env or ('EXA_API_KEY' if self.config.provider=='exa' else 'PERPLEXITY_API_KEY')
            secret=os.environ.get(env,'')
            if not secret:return ToolResult.err(self.name,'search credential unavailable')
            provider=self.config.provider
            if self.contents:
                from security.stealth import allowed_target
                if any(not allowed_target(url,self.settings)[0] for url in params.urls):return ToolResult.err(self.name,'contents URL rejected')
                path='/contents';payload={'urls':params.urls,'text':{'maxCharacters':10000},'summary':True}
            elif provider=='exa':
                path='/search';payload={'query':params.query,'numResults':params.num_results,'contents':{'text':{'maxCharacters':10000},'summary':True}}
            else:
                path='/chat/completions';payload={'model':'sonar','messages':[{'role':'user','content':params.query}],'max_tokens':2048}
            headers={'x-api-key':secret} if provider=='exa' else {'Authorization':'Bearer '+secret}
            raw,truncated=await _service_post(provider,path,payload,headers,self.config.timeout_seconds,self.config.max_output_bytes)
            raw=redact(raw,secret)
            if provider=='exa':
                sources=[]
                for row in raw.get('results',[])[:10]:
                    if isinstance(row,dict):sources.append({k:row[k] for k in ('url','title','text','summary') if k in row})
                parsed={'sources':sources,'unverified':True}
            else:
                choices=raw.get('choices',[])
                answer=choices[0].get('message',{}).get('content','') if choices else ''
                parsed={'answer':answer,'citations':raw.get('citations',[])[:20],'unverified':True}
            envelope=redact({'target':params.target,'kind':self.name,'provider':provider,'stdout':'','result':parsed,'truncated':truncated},secret)
            return evidence_result(self,params.target,envelope,success=not truncated,error='search response byte limit' if truncated else '',degraded=truncated)
        except asyncio.CancelledError:raise
        except asyncio.TimeoutError:return ToolResult(name=self.name,success=False,status='timeout',exit_code=124,error='search service timeout',outcome_unknown=True)
        except Exception:return ToolResult.err(self.name,'search service request failed')


def build_search_tools(settings):
    raw=getattr(getattr(settings,'extension_tools',None),'search',None)
    if raw is None:return []
    config=raw if isinstance(raw,SearchConfig) else SearchConfig.model_validate(raw)
    if not config.enabled:return []
    return [SearchTool(config,settings),*([SearchTool(config,settings,True)] if config.provider=='exa' else [])]
