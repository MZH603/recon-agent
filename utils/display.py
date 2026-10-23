"""Small, non-secret display projections; never forward raw tool payloads."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


DISPLAY_KEYS = frozenset({'target', 'domain', 'host', 'url', 'port', 'ports', 'path',
    'method', 'timeout', 'timeout_seconds', 'limit', 'tool', 'tools', 'name', 'names',
    'count', 'scope', 'depth', 'mode', 'max_results'})
SECRET = re.compile(r'(?i)(password|passwd|secret|token|api.?key|authorization|cookie|credential)')


def display_text(value, limit=200):
    text = str(value)
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', text)
    text = re.sub(r'(?i)\bBearer\s+\S+', 'Bearer [redacted]', text)
    text = re.sub(r'(?i)((?:password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[=:]\s*)[^\s&,;]+', r'\1[redacted]', text)
    # URLs can contain both userinfo and secret query values.
    def url(match):
        try:
            parts = urlsplit(match.group())
            host = parts.netloc.rsplit('@', 1)[-1]
            query = '&'.join(pair.split('=', 1)[0] + '=[redacted]' for pair in parts.query.split('&') if pair)
            return urlunsplit((parts.scheme, host, parts.path, query, ''))
        except ValueError:
            return '[redacted URL]'
    text = re.sub(r'https?://[^\s]+', url, text)
    return text[:limit] + ('…' if len(text) > limit else '')


def display_arguments(arguments):
    """Allow only useful display fields, with a strict total character budget."""
    if not isinstance(arguments, dict):
        return {}
    result, remaining = {}, 1800
    for key, value in list(arguments.items())[:24]:
        key = str(key)
        if SECRET.search(key):
            shown = '[redacted]'
        elif key not in DISPLAY_KEYS or isinstance(value, dict):
            shown = '[omitted]'
        elif isinstance(value, list):
            shown = ', '.join(display_text(item, 80) if isinstance(item, (str, int, float, bool)) else '[omitted]'
                              for item in value[:8])
            if len(value) > 8: shown += ', …'
        else:
            shown = display_text(value)
        if remaining < len(key) + len(shown):
            result['…'] = '[display limit]'
            break
        result[display_text(key, 40)] = shown
        remaining -= len(key) + len(shown)
    return result
