"""Keep complete tool data on disk and return a bounded, recoverable model view."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from uuid import uuid4
from security.stealth import normalize_host
from tools.runtime.evidence_store import canonical_json, evidence_store_for


def preview(value, depth=0):
    if depth > 3:
        return str(value)[:200]
    if isinstance(value, str):
        return value[:600] + ('…' if len(value) > 600 else '')
    if isinstance(value, dict):
        return {str(k)[:120]: preview(v, depth+1) for k,v in list(value.items())[:20]}
    if isinstance(value, list):
        return [preview(v, depth+1) for v in value[:20]]
    return value


class ResultPayloads:
    def __init__(self, settings):
        self.root = evidence_store_for(settings).root / 'artifacts'
        from utils.config import Settings
        self.limit = getattr(settings,'TOOL_RESULT_MAX_BYTES',Settings.model_fields['TOOL_RESULT_MAX_BYTES'].default)

    def prepare(self, result, target, *, force=False):
        result = dict(result)
        result.setdefault('status', 'success' if result.get('success') else 'failure')
        if not result.get('summary'):
            detail = result.get('error') or result.get('stdout') or json.dumps(preview(result.get('data', {})),ensure_ascii=False)
            result['summary'] = f"{result['name']} · {result['status']}：{detail[:600]}"
        # Reader pages already point at a complete immutable source. Saving a page
        # as another artifact creates an unreadable chain of artifact envelopes.
        if result.get('name') in ('artifact_read', 'evidence_get') and any(
                key in result.get('data', {}) for key in ('content', 'payload_preview')):
            return result
        if result.get('raw_artifact_id') or (not force and len(canonical_json(result)) <= self.limit):
            return result
        try:
            raw = canonical_json({'target':normalize_host(target).lower(),'result':result})
            identity = hashlib.sha256(raw).hexdigest()
            self.root.mkdir(parents=True,exist_ok=True)
            path = self.root/(identity+'.json')
            temporary = self.root/(identity+'.'+uuid4().hex+'.tmp')
            try:
                with temporary.open('xb') as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                # Immutable content IDs; replacement would only be identical bytes.
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
            artifact = {'id':identity,'path':str(path.resolve()),'type':'application/json',
                        'size_bytes':len(raw),'sha256':identity,'purpose':'完整工具结果'}
            result['artifacts'] = list(result.get('artifacts', [])) + [artifact]
            result['raw_artifact_id'] = identity
        except (OSError,ValueError,TypeError) as exc:
            result['artifact_error'] = f'完整结果保存失败：{exc}'
        return result

    def for_model(self, result):
        if len(canonical_json(result)) <= self.limit:
            return result
        data = result.get('data', {})
        field = 'content' if result.get('name') == 'artifact_read' else 'payload_preview'
        if result.get('name') in ('artifact_read', 'evidence_get') and isinstance(data.get(field), str):
            page = {k:data[k] for k in ('artifact_id','evidence_id','offset','next_offset','has_more','size_bytes','truncated') if k in data}
            brief = {'name':result['name'], 'success':result['success'], 'status':result['status'], 'data':page}
            text = data[field]
            low, high = 0, len(text)
            def candidate(length):
                page[field] = text[:length]
                page['next_offset'] = data['offset'] + len(page[field].encode('utf-8'))
                page['has_more'] = bool(data.get('has_more')) or length < len(text)
                if field == 'payload_preview': page['truncated'] = True
                return len(canonical_json(brief))
            while low < high:
                middle = (low + high + 1)//2
                if candidate(middle) <= self.limit: low = middle
                else: high = middle - 1
            candidate(low)
            return brief
        keys = ('name','success','status','summary','error','error_code','evidence','source_hash',
                'execution_id','target','min_level','cached','artifacts','raw_artifact_id',
                'elapsed_seconds','timeout_seconds','cancellation_status','outcome_unknown','artifact_error')
        brief = {k:preview(result[k]) for k in keys if k in result}
        brief['data'] = preview(result.get('data',{}))
        brief['truncated'] = True
        brief['read_hint'] = '使用 artifact_read(target, artifact_id=raw_artifact_id, offset, max_bytes) 分页读完整结果' if result.get('raw_artifact_id') else '完整结果保存失败，请勿假设存在文件'
        if len(canonical_json(brief)) > self.limit:
            brief['data'] = {'keys':list(result.get('data',{}))[:20]}
            brief['evidence'] = list(result.get('evidence',[]))[:5]
            brief['artifacts'] = list(result.get('artifacts',[]))[-1:]
            brief['summary'] = str(brief.get('summary',''))[:400]
            brief['error'] = str(brief.get('error',''))[:400]
        if len(canonical_json(brief)) > self.limit:
            # Preserve the retrieval ID and actual outcome before optional previews.
            brief = {k:result[k] for k in ('name','success','status','error_code','outcome_unknown',
                     'elapsed_seconds','timeout_seconds','cancellation_status','raw_artifact_id') if k in result}
            brief['summary'] = str(result.get('summary',''))[:120]
            brief['error'] = str(result.get('error',''))[:120]
            brief['truncated'] = True
            brief['read_hint'] = 'artifact_read: 按 raw_artifact_id 分页读取' if result.get('raw_artifact_id') else '完整结果保存失败'
            for key in ('summary','error'):
                while len(canonical_json(brief)) > self.limit and brief[key]:
                    brief[key] = brief[key][:len(brief[key])//2]
        return brief

    def read(self, identifier, target, offset, maximum):
        if not re.fullmatch(r'[0-9a-f]{64}',identifier):
            raise ValueError('invalid artifact id')
        path = self.root/(identifier+'.json')
        if path.is_symlink():
            raise ValueError('artifact symlink forbidden')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != identifier:
            raise ValueError('artifact hash mismatch')
        record = json.loads(raw)
        if record['target'] != normalize_host(target).lower():
            raise ValueError('artifact scope mismatch')
        if offset > len(raw):
            raise ValueError('offset exceeds artifact size')
        if offset < len(raw) and raw[offset] & 0xc0 == 0x80:
            raise ValueError('offset must be a UTF-8 character boundary')
        part = raw[offset:offset+maximum]
        # Preserve a valid UTF-8 boundary so consecutive pages reconstruct the bytes.
        text = part.decode('utf-8',errors='ignore')
        consumed = len(text.encode('utf-8'))
        if part and consumed == 0:
            raise ValueError('max_bytes too small for next character')
        return {'offset':offset,'next_offset':offset+consumed,'has_more':offset+consumed<len(raw),
                'size_bytes':len(raw),'content':text,'artifact_id':identifier}
