"""Bounded HTTP/1.1 GET/HEAD with scope checks and DNS-pinned connections."""
from __future__ import annotations

import asyncio
import socket
import ssl
from urllib.parse import urljoin,urlsplit

from security.stealth import allowed_target,is_in_scope,random_user_agent
from utils.config import get_settings
from platforms.sync_worker import resolve_addresses


def _origin(url):
    parsed=urlsplit(url)
    return parsed.scheme,parsed.hostname,parsed.port or (443 if parsed.scheme=='https' else 80)


def _checked_url(url,target,settings,strict_origin,origin):
    parsed=urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('HTTP URL must use http(s) without credentials')
    if any(character in url for character in ('\r','\n','\x00')): raise ValueError('invalid URL characters')
    if not is_in_scope(url,target) or (strict_origin and _origin(url)!=origin): raise ValueError('HTTP scope violation')
    ok,reason=allowed_target(url,settings)
    if not ok: raise ValueError('HTTP target rejected: '+reason)
    return parsed


async def _read_body(reader,headers,status,method,max_bytes):
    if method=='HEAD' or status in (204,304) or 100<=status<200: return b'',False
    collected=bytearray()
    if 'chunked' in headers.get('transfer-encoding','').lower():
        while True:
            line=await reader.readline()
            if len(line)>1024: raise ValueError('invalid HTTP chunk header')
            try: size=int(line.split(b';')[0].strip(),16)
            except ValueError: raise ValueError('invalid HTTP chunk length') from None
            if size<0: raise ValueError('invalid HTTP chunk length')
            if size==0: return bytes(collected),False
            need=min(size,max_bytes+1-len(collected))
            collected.extend(await reader.readexactly(need))
            if len(collected)>max_bytes: return bytes(collected[:max_bytes]),True
            if need<size: return bytes(collected),True
            if await reader.readexactly(2)!=b'\r\n': raise ValueError('invalid HTTP chunk ending')
    remaining=None
    if 'content-length' in headers:
        remaining=int(headers['content-length'])
        if remaining<0: raise ValueError('invalid HTTP content length')
    while remaining is None or remaining>0:
        need=min(65536,max_bytes+1-len(collected))
        if remaining is not None: need=min(need,remaining)
        chunk=await reader.read(need)
        if not chunk:
            if remaining: raise ValueError('incomplete HTTP body')
            break
        collected.extend(chunk)
        if remaining is not None: remaining-=len(chunk)
        if len(collected)>max_bytes: return bytes(collected[:max_bytes]),True
    return bytes(collected),False


async def _request_chain(url,target,settings,method,headers,max_bytes,max_redirects,strict_origin,tracker):
    origin=_origin(url)
    request_count=0
    for hop in range(max_redirects+1):
        parsed=_checked_url(url,target,settings,strict_origin,origin)
        port=parsed.port or (443 if parsed.scheme=='https' else 80)
        addresses=await resolve_addresses(parsed.hostname,port)
        if not addresses: raise ValueError('HTTP hostname has no resolved address')
        for info in addresses:
            ok,reason=allowed_target(info[4][0],settings)
            if not ok: raise ValueError('HTTP resolved address rejected: '+reason)
        # Use the inspected numeric address directly; TLS still validates the original hostname.
        ip=addresses[0][4][0]
        context=ssl.create_default_context() if parsed.scheme=='https' else None
        reader,writer=await asyncio.open_connection(ip,port,ssl=context,server_hostname=parsed.hostname if context else None,limit=65536)
        try:
            hostname=parsed.hostname
            if ':' in hostname: hostname='['+hostname+']'
            host=hostname+(f':{port}' if port!=(443 if context else 80) else '')
            supplied={'User-Agent':random_user_agent(),**(headers or {})}
            if any(key.lower() in ('host','connection','content-length','transfer-encoding') for key in supplied): raise ValueError('reserved HTTP header')
            for key,value in supplied.items():
                if any(c in str(key)+str(value) for c in ('\r','\n','\x00')): raise ValueError('invalid HTTP header')
            path=parsed.path or '/'
            if parsed.query: path+='?'+parsed.query
            request=f'{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n'+''.join(f'{k}: {v}\r\n' for k,v in supplied.items())+'\r\n'
            writer.write(request.encode('ascii')); request_count+=1; tracker['request_count']=request_count
            await writer.drain()
            block=await reader.readuntil(b'\r\n\r\n')
            if len(block)>65536: raise ValueError('HTTP header byte limit')
            lines=block.decode('iso-8859-1').split('\r\n')
            status=int(lines[0].split()[1]); response_headers={}
            for line in lines[1:]:
                if not line: continue
                key,value=line.split(':',1); response_headers[key.lower()]=value.strip()
            if status in (301,302,303,307,308) and 'location' in response_headers:
                next_url=urljoin(url,response_headers['location'])
                _checked_url(next_url,target,settings,strict_origin,origin)
                if hop>=max_redirects: raise ValueError('HTTP redirect limit')
                # Never forward credential headers across origins.
                if _origin(next_url)!=_origin(url): headers={}
                url=next_url
                continue
            body,truncated=await _read_body(reader,response_headers,status,method,max_bytes)
            return {'url':url,'status':status,'status_code':status,'headers':response_headers,'body':body,'truncated':truncated,'request_count':request_count}
        finally:
            writer.close()
            try: await writer.wait_closed()
            except (OSError,ssl.SSLError): pass
    raise ValueError('HTTP redirect limit')


async def guarded_http_get(url,target,*,settings=None,timeout=10.0,max_bytes=100000,max_redirects=3,strict_origin=False,method='GET',headers=None):
    if method not in ('GET','HEAD'): raise ValueError('only GET/HEAD permitted')
    if not 1<=max_bytes<=2097152 or not 0<=max_redirects<=10 or timeout<=0: raise ValueError('invalid HTTP bounds')
    tracker={'request_count':0}
    try:
        return await asyncio.wait_for(_request_chain(url,target,settings or get_settings(),method,headers,max_bytes,max_redirects,strict_origin,tracker),timeout)
    except BaseException as exc:
        exc.request_count=tracker['request_count']
        raise


async def guarded_request(url,settings,scope,method='GET',headers=None,max_bytes=102400,timeout=10,**kwargs):
    return await guarded_http_get(url,scope,settings=settings,method=method,headers=headers,max_bytes=max_bytes,timeout=timeout,**kwargs)
