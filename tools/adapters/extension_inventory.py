"""Inspect configured optional capabilities without creating any clients."""
import os

from tools.adapters.offline_status import _executable_status
from tools.adapters.scanners import NAMES


def configured_extension_rows(profile):
    rows = [dict(id='extension:' + item.kind, name=NAMES[item.kind], kind='extension:command',
        enabled=item.enabled, min_level=0 if item.kind == 'subfinder' else 2,
        status=_executable_status(item.executable or item.kind)) for item in profile.extension_tools.scanners]
    search = profile.extension_tools.search
    if search is not None:
        key = search.api_key_env or ('EXA_API_KEY' if search.provider == 'exa' else 'PERPLEXITY_API_KEY')
        rows.append(dict(id='extension:search', name='web_search (' + search.provider + ')', kind='extension:search',
            enabled=search.enabled, min_level=0, status='configured-http' if os.environ.get(key) else 'requires-api-key'))
    if profile.extension_tools.caido is not None:
        ready = bool(os.environ.get(profile.extension_tools.caido.token_env))
        rows.append(dict(id='extension:caido', name='Caido 只读查询', kind='extension:proxy',
            enabled=profile.extension_tools.caido.enabled, min_level=0,
            status='configured-http' if ready else 'requires-api-key'))
    return rows
