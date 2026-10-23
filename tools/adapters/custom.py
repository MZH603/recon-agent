"""Trusted configured adapters: literal argv, validated scripts, HTTP, and shell hints."""
from __future__ import annotations

import asyncio
import json
import os
import string
import sys
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator
from pydantic import BaseModel,ConfigDict,Field

from platforms.subprocess import kill_and_reap, spawn_owned, release_process
from platforms.tools import find_tool
from scripts import sandbox
from security.stealth import StealthRateLimiter
from utils.config import Settings
from tools.base import BaseTool,ToolResult
from tools.runtime.evidence_store import MAX_EVIDENCE_BYTES, canonical_json, evidence_store_for
from tools.adapters.integration_config import CUSTOM_PROTECTED_ARGUMENTS, CustomToolConfig
from tools.adapters.integration_http import guarded_http_get


class CustomToolParams(BaseModel):
    model_config=ConfigDict(extra='forbid')
    target: str=Field(min_length=1,max_length=2048)
    arguments: dict=Field(default_factory=dict)


def _template(value,values):
    output=[]
    for literal,field,_,_ in string.Formatter().parse(value):
        output.append(literal)
        if field is not None:
            item=values[field]
            if not isinstance(item,(str,int,float,bool)) and item is not None: raise ValueError('placeholder must be scalar')
            output.append(str(item))
    return ''.join(output)


def _environment(mapping):
    mapped={}; secrets=[]
    for key,source in mapping.items():
        value=os.environ.get(source)
        if value is None: raise ValueError('required environment variable unavailable')
        mapped[key]=value
        if value: secrets.append(value)
    return mapped,secrets


def _redact(value,secrets):
    if isinstance(value,str):
        for secret in sorted(secrets,key=len,reverse=True): value=value.replace(secret,'[REDACTED]')
        return value
    if isinstance(value,dict): return {_redact(str(k),secrets):_redact(v,secrets) for k,v in value.items()}
    if isinstance(value,list): return [_redact(v,secrets) for v in value]
    return value


async def _bounded_process(argv,timeout,max_bytes,env=None,input_data=None):
    proc=await spawn_owned(*argv,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,env=env)
    captured=[bytearray(),bytearray()]; consumed=0; truncated=False
    async def drain(stream,index):
        nonlocal consumed,truncated
        while True:
            chunk=await stream.read(65536)
            if not chunk: return
            keep=max(0,max_bytes-consumed)
            captured[index].extend(chunk[:keep]); consumed+=min(len(chunk),keep)
            if len(chunk)>keep: truncated=True
    async def feed():
        if input_data is not None:
            try:
                proc.stdin.write(input_data.encode()); await proc.stdin.drain()
            except (BrokenPipeError,ConnectionResetError): pass
            finally: proc.stdin.close()
    tasks=[asyncio.create_task(drain(proc.stdout,0)),asyncio.create_task(drain(proc.stderr,1)),asyncio.create_task(feed())]
    try:
        await asyncio.wait_for(asyncio.gather(proc.wait(),*tasks),timeout)
        code=proc.returncode
    except asyncio.TimeoutError:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await kill_and_reap(proc); code=124
    except asyncio.CancelledError:
        from tools.runtime.execution_wait import partial_output
        partial=partial_output.get()
        if partial is not None:
            clean=partial.get('_redactor',lambda value:value)
            partial.update(clean({'stdout':bytes(captured[0]).decode('utf-8',errors='ignore'),
                                  'stderr':bytes(captured[1]).decode('utf-8',errors='ignore')}))
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await kill_and_reap(proc); raise
    finally:
        release_process(proc)
    return code,bytes(captured[0]).decode('utf-8',errors='ignore'),bytes(captured[1]).decode('utf-8',errors='ignore'),truncated


class CustomTool(BaseTool):
    cacheable=False
    params_model=CustomToolParams
    def __init__(self,config,settings):
        self.config=config; self.settings=settings; self.name=config.name
        self.description=config.description or f'Configured {config.kind} tool'
        self.min_level=config.min_level; self.risk_level='高' if self.min_level==2 else '低'
        self.deferred=config.deferred; self.store=evidence_store_for(settings)
        self._limiter=StealthRateLimiter(
            getattr(settings,'REQUEST_DELAY_RANGE',Settings.model_fields['REQUEST_DELAY_RANGE'].default),
            getattr(settings,'MAX_CONCURRENCY',Settings.model_fields['MAX_CONCURRENCY'].default)) if config.kind=='http' else None

    def to_openai_spec(self):
        spec=super().to_openai_spec()
        spec['function']['parameters']['properties']['arguments']=self.config.input_schema
        return spec

    async def _http(self,url,target,headers):
        async with self._limiter.slot():
            return await guarded_http_get(url,target,settings=self.settings,
                timeout=self.config.timeout_seconds,max_bytes=self.config.max_output_bytes,
                method=self.config.method,headers=headers)

    async def _script(self,values,env):
        code='import json\n'+'target = '+repr(values['target'])+'\narguments = json.loads('+repr(json.dumps({k:v for k,v in values.items() if k!='target'}))+')\nRECON_INPUT = dict(target=target, arguments=arguments)\n'+self.config.script
        if not getattr(self.settings,'SANDBOX_ENABLED',True): raise ValueError('sandbox disabled')
        check=sandbox.validate_script(code)
        if not check.allowed: raise ValueError('sandbox AST rejected: '+check.reason)
        with tempfile.TemporaryDirectory(prefix='recon-custom-') as folder:
            work=Path(folder)
            findings=await sandbox.run_bandit(code,work)
            if findings: raise ValueError('sandbox Bandit rejected script')
            docker=find_tool('docker') if getattr(self.settings,'SANDBOX_USE_DOCKER',False) else None
            timeout=min(self.config.timeout_seconds,getattr(self.settings,'SANDBOX_TIMEOUT',30))
            if docker:
                argv=[docker,'run','--rm','-i','--network='+getattr(self.settings,'SANDBOX_NETWORK','none'),'--read-only','--user=1000','--cap-drop=ALL','--security-opt=no-new-privileges','--memory='+getattr(self.settings,'SANDBOX_MEMORY_LIMIT','128m'),'python:3.11-slim']
                result=await _bounded_process(argv,timeout,self.config.max_output_bytes,env=env,input_data=code)
                return (*result,'docker')
            script=work/'candidate_script.py'; script.write_text(code,encoding='utf-8')
            result=await _bounded_process([sys.executable,'-I',str(script)],timeout,self.config.max_output_bytes,env=env)
            return (*result,'host')

    async def run(self,params):
        config=self.config; secrets=[]; isolation=None
        try:
            if CUSTOM_PROTECTED_ARGUMENTS.intersection(params.arguments):
                return ToolResult.err(self.name,'protected tool arguments cannot be overridden')
            errors=list(Draft202012Validator(config.input_schema).iter_errors(params.arguments))
            if errors: return ToolResult.err(self.name,'argument JSON schema validation failed')
            values={**params.arguments,'target':params.target}
            mapped,secrets=_environment(config.env)
            headers,header_secrets=_environment(config.headers_env); secrets.extend(header_secrets)
            from tools.runtime.execution_wait import partial_output
            partial=partial_output.get()
            if partial is not None: partial['_redactor']=lambda value:_redact(value,secrets)
            if config.kind=='shell':
                return ToolResult(name=self.name,success=True,data={'executed':False,'argv':[_redact(_template(v,values),secrets) for v in config.command]})
            if config.kind=='http':
                response=await asyncio.wait_for(self._http(_template(config.url,values),params.target,headers),config.timeout_seconds)
                out=response.pop('body').decode('utf-8',errors='ignore'); err=''; code=0 if 200<=response['status']<400 else response['status']
                truncated=response['truncated']; context=response
                sensitive={'set-cookie','authorization','proxy-authorization','cookie'}
                context['headers']={key:('[REDACTED]' if key.lower() in sensitive else value) for key,value in context['headers'].items()}
            else:
                env={**os.environ,**mapped}
                if config.kind=='script': code,out,err,truncated,isolation=await asyncio.wait_for(self._script(values,env),config.timeout_seconds)
                else: code,out,err,truncated=await _bounded_process([_template(v,values) for v in config.command],config.timeout_seconds,config.max_output_bytes,env=env)
                context={'exit_code':code}
                if isolation: context['isolation']=isolation
            out=_redact(out,secrets); err=_redact(err,secrets)
            if config.response_format=='json' and not truncated: parsed=json.loads(out)
            elif config.response_format=='jsonl' and not truncated: parsed=[json.loads(line) for line in out.splitlines() if line.strip()]
            else: parsed=out
            clean_parsed=_redact(parsed,secrets)
            if clean_parsed!=parsed and not truncated:
                # Decoding may expose Unicode-escaped secrets that raw text matching
                # cannot see. Retain the complete sanitized JSON rather than escapes.
                if config.response_format=='json': out=canonical_json(clean_parsed).decode('utf-8')
                elif config.response_format=='jsonl': out='\n'.join(canonical_json(item).decode('utf-8') for item in clean_parsed)
            parsed=clean_parsed
            payload=_redact({'tool':self.name,'target':params.target,'stdout':out,'stderr':err,**context,'truncated':truncated},secrets)
            # Escaping can multiply raw stream bytes by six. The complete retained
            # evidence envelope must fit too; never silently hash only a preview.
            while len(canonical_json(payload))>MAX_EVIDENCE_BYTES:
                out=out[:len(out)*3//4]; err=err[:len(err)*3//4]; truncated=True
                payload.update(stdout=out,stderr=err,truncated=True)
            if truncated: parsed=out
            evidence_id=self.store.put(params.target,self.name,payload); record=self.store.get(evidence_id)
            return ToolResult(name=self.name,success=code==0,stdout=out,stderr=err,exit_code=code,data={**payload,'output':parsed,'evidence_id':evidence_id},
                evidence=[f'local:{evidence_id}'],source_hash=record['sha256'],degraded=truncated or isolation=='host',
                error='command timeout' if code==124 else ('command failed' if code else ''))
        except asyncio.CancelledError:
            # Streams already captured by the process adapter may contain secrets.
            from tools.runtime.execution_wait import partial_output
            captured=partial_output.get()
            if captured:
                captured.update(_redact(captured,secrets))
            raise
        except asyncio.TimeoutError:
            return ToolResult(name=self.name,success=False,exit_code=124,error='custom tool timeout')
        except Exception as exc:
            # Never include argv, header values, source env values, or arbitrary exception text.
            return ToolResult.err(self.name,'custom tool failed: '+type(exc).__name__)


def build_custom_tools(settings):
    result=[]; names=set()
    for raw in getattr(settings,'custom_tools',[]):
        config=raw if isinstance(raw,CustomToolConfig) else CustomToolConfig.model_validate(raw)
        if not config.enabled: continue
        if config.name in names: raise ValueError('duplicate custom tool name')
        names.add(config.name); result.append(CustomTool(config,settings))
    return result
