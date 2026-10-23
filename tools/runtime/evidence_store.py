"""Content addressed, bounded local JSON evidence with immutable scope binding."""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime,timezone
from pathlib import Path
from typing import Any

from security.stealth import normalize_host

MAX_EVIDENCE_BYTES=2097152

def canonical_json(value: Any)->bytes:
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def evidence_store_for(settings):
    return EvidenceStore(getattr(settings,'TOOL_EVIDENCE_DIR','') or None)


class EvidenceStore:
    def __init__(self,root=None):
        self.root=Path(root) if root else Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'.cache')))/'recon-agent'/'evidence'

    def put(self,target: str,kind: str,payload: Any)->str:
        target=normalize_host(target).lower()
        if not target or not kind: raise ValueError('target and kind required')
        raw=canonical_json(payload)
        if len(raw)>MAX_EVIDENCE_BYTES: raise ValueError('evidence payload exceeds byte limit')
        digest=hashlib.sha256(raw).hexdigest()
        evidence_id=hashlib.sha256(canonical_json({'target':target,'kind':kind,'sha256':digest})).hexdigest()
        record={'evidence_id':evidence_id,'target':target,'kind':kind,'created_at':datetime.now(timezone.utc).isoformat(),'sha256':digest,'size_bytes':len(raw),'payload':payload}
        self.root.mkdir(parents=True,exist_ok=True)
        path=self.root/(evidence_id+'.json')
        temporary=self.root/('.'+evidence_id+'.'+uuid.uuid4().hex+'.tmp')
        try:
            with temporary.open('xb') as handle:
                handle.write(canonical_json(record))
                handle.flush()
                os.fsync(handle.fileno())
            try:
                if os.name=='nt':
                    # Windows rename atomically publishes and refuses replacement.
                    os.rename(temporary,path)
                else:
                    # POSIX rename replaces existing files; link publishes atomically
                    # with exclusive creation instead, keeping content IDs immutable.
                    os.link(temporary,path)
            except FileExistsError:
                self.get(evidence_id,target=target)
        finally:
            temporary.unlink(missing_ok=True)
        return evidence_id

    def get(self,evidence_id: str,target: str|None=None)->dict:
        if not re.fullmatch(r'[0-9a-f]{64}',evidence_id): raise ValueError('invalid evidence id')
        path=self.root/(evidence_id+'.json')
        if path.is_symlink(): raise ValueError('evidence symlink forbidden')
        if path.stat().st_size>MAX_EVIDENCE_BYTES+8192: raise ValueError('evidence file exceeds byte limit')
        record=json.loads(path.read_bytes())
        raw=canonical_json(record['payload'])
        digest=hashlib.sha256(raw).hexdigest()
        identity=hashlib.sha256(canonical_json({'target':record['target'],'kind':record['kind'],'sha256':digest})).hexdigest()
        if digest!=record['sha256'] or identity!=evidence_id or record.get('evidence_id')!=evidence_id or len(raw)!=record['size_bytes']:
            raise ValueError('evidence hash mismatch')
        if target is not None and record['target']!=normalize_host(target).lower(): raise ValueError('evidence scope mismatch')
        return record

    def search(self,target: str,query: str='',limit: int=10)->list[dict]:
        if limit<1 or limit>100: raise ValueError('limit must be 1..100')
        if not self.root.exists(): return []
        result=[]
        for path in sorted(self.root.glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True):
            try: record=self.get(path.stem,target=target)
            except (ValueError,KeyError,FileNotFoundError,json.JSONDecodeError): continue
            if query.casefold() not in canonical_json(record).decode().casefold(): continue
            result.append({key:value for key,value in record.items() if key!='payload'})
            if len(result)>=limit: break
        return result
