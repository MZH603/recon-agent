"""Read-only, scope-filtered Caido metadata via bounded fixed GraphQL reads.

Sitemap observations are derived from one bounded history page. The upstream
native sitemap API has no server pagination; fetching its entire tree would
violate the adapter's bounded-read contract.
"""
from __future__ import annotations

import asyncio
import os
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator
from tools.base import BaseTool, ToolResult
from tools.adapters.scanners import checked_target, evidence_result, in_scope
from tools.adapters.search import bounded_json_post, redact

_FIELDS='id host port method path query is_tls:isTls response { status_code:statusCode }'
_LIST_QUERY='query ReconHistory($first:Int!,$after:String) { requests(first:$first,after:$after) { edges { node { '+_FIELDS+' } } page_info:pageInfo { has_next_page:hasNextPage end_cursor:endCursor } } }'
_VIEW_QUERY='query ReconRequest($id:ID!) { request(id:$id) { '+_FIELDS+' } }'


class CaidoConfig(BaseModel):
    model_config=ConfigDict(extra='forbid')
    enabled: bool=False
    url: str='http://127.0.0.1:48080'
    token_env: str=Field('CAIDO_TOKEN',pattern=r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')
    timeout_seconds: float=Field(30,ge=1,le=120)
    max_output_bytes: int=Field(100000,ge=128,le=262144)

    @field_validator('url')
    @classmethod
    def fixed_service_url(cls,value):
        p=urlsplit(value)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('','/') or any(c in value for c in '\r\n\x00\\'):
            raise ValueError('Caido URL must be a fixed HTTP service origin')
        _=p.port
        return value.rstrip('/')


class ProxyListParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    limit: int=Field(30,ge=1,le=50)
    after: str|None=Field(None,max_length=256)


class ProxyViewParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    request_id: str=Field(min_length=1,max_length=128,pattern=r'^[A-Za-z0-9_-]+$')


class CaidoManager:
    def __init__(self,config):
        self.config=config;self.lock=asyncio.Lock();self.closed=False

    async def call(self,params,view=False):
        async with self.lock:
            if self.closed:raise ValueError('Caido manager closed')
            token=os.environ.get(self.config.token_env,'')
            if not token:raise ValueError('Caido credential unavailable')
            query=_VIEW_QUERY if view else _LIST_QUERY
            variables={'id':params.request_id} if view else {'first':params.limit,'after':params.after}
            raw,truncated=await bounded_json_post(self.config.url,'/graphql',{'query':query,'variables':variables},
                {'Authorization':'Bearer '+token},self.config.timeout_seconds,self.config.max_output_bytes)
            if truncated:raise ValueError('Caido response byte limit')
            if raw.get('errors'):raise ValueError('Caido metadata query rejected')
            data=redact(raw.get('data',{}),token)
            return data.get('request') if view else data.get('requests',{})

    async def aclose(self):
        async with self.lock:
            self.closed=True


def _field(value,name,default=None):
    return value.get(name,default) if isinstance(value,dict) else getattr(value,name,default)


def _request_summary(node,target,settings):
    req=_field(node,'request',node);response=_field(node,'response')
    if req is None:return None
    host=str(_field(req,'host',''))
    port=_field(req,'port',443 if _field(req,'is_tls',False) else 80)
    scheme='https' if _field(req,'is_tls',False) else 'http'
    path=str(_field(req,'path','/'))
    # Avoid urljoin: a captured absolute or // path must never replace the host.
    if not path.startswith('/') or path.startswith('//') or any(c in path for c in '\r\n\x00\\'):
        return None
    authority=('['+host+']') if ':' in host else host
    url=f'{scheme}://{authority}:{port}{path.split("?",1)[0]}'
    if not in_scope(url,target,settings):return None
    query=str(_field(req,'query','') or (path.split('?',1)[1] if '?' in path else ''))
    params=sorted({name[:100] for name,_ in parse_qsl(query,keep_blank_values=True,max_num_fields=100)})
    status=_field(response,'status_code')
    return {'url':url,'host':host,'method':str(_field(req,'method','GET'))[:20],
        'status':status if isinstance(status,int) else None,'candidate':not isinstance(status,int),
        'request_id':str(_field(req,'id',''))[:128], 'body_omitted':True,'query_redacted':True,'params':params}


class CaidoTool(BaseTool):
    remote_execution=True
    deferred=True
    cacheable=False
    min_level=0

    def __init__(self,name,config,settings,manager):
        self.name=name;self.config=config;self.settings=settings;self.manager=manager
        self.params_model=ProxyViewParams if name=='view_request' else ProxyListParams
        self.description='Read-only scoped Caido '+name+'; credentials, queries and captured bodies omitted'

    async def aclose(self):
        await self.manager.aclose()

    async def run(self,params):
        try:
            checked_target(params.target,self.settings)
            view=self.name=='view_request'
            response=await asyncio.wait_for(self.manager.call(params,view),self.config.timeout_seconds)
            if view:
                item=_request_summary(response,params.target,self.settings)
                if item is None:return ToolResult.err(self.name,'captured request outside target scope or unavailable')
                rows=[item];more=False;after=None
            else:
                edges=_field(response,'edges',[])
                rows=[]
                for edge in edges[:params.limit]:
                    item=_request_summary(_field(edge,'node'),params.target,self.settings)
                    if item is not None:rows.append(item)
                page=_field(response,'page_info')
                more=bool(_field(page,'has_next_page',False));after=_field(page,'end_cursor')
            parsed={'requests':rows,'has_more':more,'after':str(after)[:256] if after else None}
            if self.name=='list_sitemap':
                parsed.update(endpoints=list(dict.fromkeys(row['url'] for row in rows)),derived_from='bounded captured request history',complete=False)
            from tools.runtime.evidence_store import canonical_json
            truncated=False
            while len(canonical_json(parsed))>self.config.max_output_bytes and parsed['requests']:
                parsed['requests'].pop();truncated=True
                if 'endpoints' in parsed:parsed['endpoints']=[row['url'] for row in parsed['requests']]
            envelope={'target':params.target,'kind':self.name,'stdout':'','result':parsed,'truncated':truncated}
            return evidence_result(self,params.target,envelope,degraded=truncated)
        except asyncio.CancelledError:raise
        except asyncio.TimeoutError:return ToolResult(name=self.name,success=False,status='timeout',exit_code=124,error='Caido service timeout',outcome_unknown=True)
        except ValueError as exc:
            known=str(exc)
            if known in ('Caido credential unavailable','Caido manager closed','Caido response byte limit'):
                return ToolResult.err(self.name,known)
            return ToolResult.err(self.name,'Caido request rejected')
        except Exception:return ToolResult.err(self.name,'Caido service request failed')


def build_proxy_tools(settings):
    raw=getattr(getattr(settings,'extension_tools',None),'caido',None)
    if raw is None:return []
    config=raw if isinstance(raw,CaidoConfig) else CaidoConfig.model_validate(raw)
    if not config.enabled:return []
    manager=CaidoManager(config)
    return [CaidoTool(name,config,settings,manager) for name in ('list_requests','view_request','list_sitemap')]
