"""Conservative static JavaScript hints; never execute downloaded JavaScript."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

MAX_PARSE_ITEMS = 1000
MAX_CALL_SPAN = 4096

_QUOTES = re.compile(r'''["'`]([^"'`\r\n]+)["'`]''')
_API_PATH = re.compile(r'^/(?:api(?:/|$)|graphql(?:/|$)|v\d+(?:/|$)|rest(?:/|$))', re.I)
_CALL = re.compile(r'''\b(fetch|axios(?:\.(get|post|put|patch|delete|head|options))?)\s*\(\s*["'`]([^"'`]+)["'`]''', re.I)


def _path_and_params(value: str) -> tuple[str, list[str]]:
    parts = urlsplit(value)
    return parts.path or '/', sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})


def _local_literal(value: str, source_url: str) -> bool:
    if not value.startswith(('/', 'http://', 'https://')):
        return False
    try:
        candidate, source = urlsplit(urljoin(source_url, value)), urlsplit(source_url)
        def origin(parts):
            return parts.scheme.lower(), (parts.hostname or '').lower(), parts.port or (443 if parts.scheme == 'https' else 80)
        return not (candidate.username or candidate.password) and origin(candidate) == origin(source)
    except ValueError:
        return False


def _argument_tail(text: str, start: int, limits: dict | None = None) -> str:
    """Stop at this call's balanced closing parenthesis, ignoring quoted text."""
    depth = 1
    quote = ''
    escaped = False
    for index in range(start, min(len(text), start + MAX_CALL_SPAN)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == chr(92):
                escaped = True
            elif char == quote:
                quote = ''
        elif char in ('"', "'", '`'):
            quote = char
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return text[start:index]
    if limits is not None:
        limits['truncated'] = True
    return text[start:start + MAX_CALL_SPAN]


def extract_api_records(text: str, source_url: str, *, limits: dict | None = None) -> tuple[list[dict], list[str]]:
    """Return candidate endpoints and separate frontend route literals.

    Explicit fetch/axios calls give method candidates; generic API strings retain
    unknown methods. Parameters are names only, without requiredness inference.
    """
    limits = limits if limits is not None else {}
    records: list[dict] = []
    called: set[str] = set()
    for index, match in enumerate(_CALL.finditer(text)):
        if index >= MAX_PARSE_ITEMS:
            limits['truncated'] = True
            break
        value = match.group(3)
        if not _local_literal(value, source_url):
            continue
        call_limits = {}
        snippet = _argument_tail(text, match.end(), call_limits)
        incomplete = bool(call_limits.get('truncated'))
        if incomplete:
            limits['truncated'] = True
        method = match.group(2).upper() if match.group(2) else ('GET' if match.group(1).lower() == 'fetch' else None)
        explicit = re.search(r'''\bmethod\s*:\s*["']([A-Z]+)["']''', snippet, re.I)
        if incomplete:
            method = None
        elif explicit:
            method = explicit.group(1).upper()
        path, params = _path_and_params(value)
        body = re.search(r'JSON\.stringify\s*\(\s*\{([^{}]*)\}', snippet)
        if body is None and match.group(1).lower().startswith('axios.') and method not in ('GET', 'HEAD'):
            body = re.search(r'^\s*,\s*\{([^{}]*)\}', snippet)
        if body:
            params = sorted(set(params) | set(re.findall(r'''(?:["']?)([A-Za-z_$][\w$]*)(?:["']?)\s*:''', body.group(1))))
        records.append({'method': method, 'path': path, 'params': params, 'source': source_url, 'observed': False})
        called.add(value)
    for index, match in enumerate(_QUOTES.finditer(text)):
        if index >= MAX_PARSE_ITEMS:
            limits['truncated'] = True
            break
        value = match.group(1)
        if value in called or not _local_literal(value, source_url):
            continue
        path, params = _path_and_params(value)
        if _API_PATH.match(path):
            records.append({'method': None, 'path': path, 'params': params, 'source': source_url, 'observed': False})
    routes = []
    for index, match in enumerate(re.finditer(r"\bpath\s*:\s*[\"'](/[^\"']*)[\"']", text)):
        if index >= MAX_PARSE_ITEMS:
            limits['truncated'] = True
            break
        if not _API_PATH.match(match.group(1)):
            routes.append(match.group(1))
    routes = sorted(set(routes))
    if len(records) > MAX_PARSE_ITEMS:
        limits['truncated'] = True
        records = records[:MAX_PARSE_ITEMS]
    return _unique_records(records), routes


def _unique_records(records: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    result = []
    for item in records:
        key = (item['method'], item['path'], tuple(item['params']), item['source'], item['observed'])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


class _ScriptLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag.lower() == 'script' and values.get('src'):
            self.links.append(values['src'])
        if tag.lower() == 'link' and values.get('rel', '').lower() in ('modulepreload', 'preload'):
            if values.get('href') and (values.get('as') == 'script' or values.get('rel') == 'modulepreload'):
                self.links.append(values['href'])


def javascript_assets(text: str, source_url: str, *, html: bool = False, limits: dict | None = None) -> list[str]:
    """Find script links, literal imports, Vite deps and common webpack maps."""
    limits = limits if limits is not None else {}
    refs: list[str] = []
    if html:
        parser = _ScriptLinks()
        parser.feed(text)
        refs.extend(parser.links)
    for index, match in enumerate(_QUOTES.finditer(text)):
        if index >= MAX_PARSE_ITEMS:
            limits['truncated'] = True
            break
        value = match.group(1)
        if re.search(r'\.(?:m?js)(?:\?[^\s]*)?$', value, re.I) and '${' not in value:
            refs.append(value)
    # webpack chunk factories: named-map + hash-map, or id + hash-map.
    for factory in re.finditer(r'\.u\s*=\s*(.*?)(?:;|\n|$)', text):
        expression = factory.group(1)
        maps: list[dict[str, str]] = []
        for raw in re.findall(r'\{([^{}]+)\}', expression):
            mapping = dict(re.findall(r'''["']?([\w-]+)["']?\s*:\s*["']([^"']+)["']''', raw))
            if mapping:
                maps.append(mapping)
        public = re.search(r'''\.p\s*=\s*["']([^"']*)["']''', text)
        prefix = public.group(1) if public else ''
        if maps and '.js' in expression:
            keys = set.intersection(*(set(mapping) for mapping in maps))
            for key in sorted(keys):
                if len(maps) >= 2:
                    filename = '.'.join(mapping[key] for mapping in maps) + '.js'
                else:
                    filename = key + '.' + maps[0][key] + '.js'
                refs.append(prefix + filename)
    if len(refs) > MAX_PARSE_ITEMS:
        limits['truncated'] = True
    urls = []
    seen = set()
    for ref in refs[:MAX_PARSE_ITEMS]:
        if ref.startswith('assets/') and urlsplit(source_url).path.startswith('/assets/'):
            ref = '/' + ref
        url = urljoin(source_url, ref)
        if urlsplit(url).scheme in ('http', 'https') and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls
