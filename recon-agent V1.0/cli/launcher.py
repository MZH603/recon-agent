"""Single-process startup credentials and atomic, nonsecret user defaults."""
from __future__ import annotations

import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, SecretStr

from model.registry import ModelSpec, resolve_model
from platforms.paths import get_config_dir
from security.stealth import allowed_target
from utils.config import optional_api_key

LIMITS = {'api_base': 2048, 'model': 256, 'target': 2048, 'api_key': 4096}
SETUP_FIELDS = {'type', 'api_base', 'model', 'target', 'api_key', 'authorized'}
ERRORS = {
    'form': '配置格式无效，请重新填写。',
    'api_base': '请输入 HTTP/HTTPS API 根地址；禁止凭据、查询、片段或 chat/completions 路径。',
    'model': '请输入有效的单行模型名（最多 256 字符）。',
    'target': '请输入有效且允许的域名/IP/URL/CIDR；自有内网实验目标需 --lab。',
    'api_key': '请输入本次使用的有效单行 API Key（最多 4096 字符）。',
    'authorized': '请明确确认已获本次目标的合法授权。',
}


def valid_text(value, field, *, empty=False):
    return (isinstance(value, str) and len(value) <= LIMITS[field] and
            (empty or bool(value.strip())) and
            all(ord(c) >= 32 and not 127 <= ord(c) <= 159 for c in value))


class SetupDefaults(BaseModel):
    api_base: str
    model: str
    target: str = ''
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)

    def public(self):
        return {'api_base': self.api_base, 'model': self.model, 'target': self.target,
                'key_available': bool(self.api_key)}


class SetupResult(BaseModel):
    target: str
    connection: ModelSpec = Field(exclude=True, repr=False)

    def public(self):
        return {'api_base': self.connection.api_base, 'model': self.connection.model,
                'target': self.target}


def load_defaults(config_dir: Path | None = None):
    path = (config_dir or get_config_dir()) / 'launcher.json'
    try:
        if path.stat().st_size > 16384:
            return {}
        value = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(value, dict) or set(value) != {'api_base', 'model', 'target'} or
                not all(valid_text(value[k], k, empty=k == 'target') for k in value)):
            return {}
        return value
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}


def save_defaults(value, config_dir: Path | None = None):
    """Whitelist fields even if called with a larger object; replace on same volume."""
    saved = {k: value[k] for k in ('api_base', 'model', 'target')}
    if not all(valid_text(saved[k], k, empty=k == 'target') for k in saved):
        raise ValueError('Invalid launcher defaults')
    directory = config_dir or get_config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory,
                                         prefix='.launcher-', suffix='.tmp', delete=False) as stream:
            name = stream.name
            json.dump(saved, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, directory / 'launcher.json')
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


def prefill(settings, model=None, target=None, *, config_dir=None):
    saved = load_defaults(config_dir)
    primary = resolve_model(settings, model)
    key = primary.api_key or optional_api_key(os.environ.get(primary.api_key_env or ''))
    # resolve_model supplies the current primary credentials; saved nonsecret values
    # take precedence over YAML defaults, but never over explicit/environment input.
    return SetupDefaults(
        model=model or os.environ.get('RECON_MODEL', '').strip() or saved.get('model') or primary.model,
        api_base=os.environ.get('RECON_API_BASE', '').strip() or saved.get('api_base') or
                 primary.api_base or 'https://api.openai.com/v1',
        target=target or saved.get('target', ''), api_key=key)


def valid_api_base(value):
    if not valid_text(value, 'api_base') or any(c.isspace() for c in value):
        return False
    try:
        url = urlsplit(value)
        return (url.scheme in ('http', 'https') and bool(url.hostname) and
                url.port != 0 and url.username is None and url.password is None and not (url.query or url.fragment) and
                not url.path.rstrip('/').lower().endswith('/chat/completions') and
                '?' not in value and '#' not in value and '\\' not in value)
    except ValueError:
        return False


def _special_networks(version):
    """Use the same registry ranges as ipaddress.is_global on each Python version.

    Network.is_global tests endpoints, so ranges must also be checked for overlap.
    Keep the version-dependent stdlib detail here, with a conservative fallback.
    """
    address = ipaddress.ip_address('0.0.0.0' if version == 4 else '::')
    constants = getattr(address, '_constants', None)
    fallback = {
        4: ('0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
            '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '240.0.0.0/4'),
        6: ('::/128', '::1/128', '::ffff:0:0/96', '64:ff9b:1::/48', '100::/64',
            '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', 'fc00::/7', 'fe80::/10'),
    }
    ranges = getattr(constants, '_private_networks', None)
    exceptions = getattr(constants, '_private_networks_exceptions', ())
    if ranges is None:
        ranges = [ipaddress.ip_network(value) for value in fallback[version]]
        fallback_exceptions = {
            4: ('192.0.0.9/32', '192.0.0.10/32'),
            6: ('2001:1::1/128', '2001:1::2/128', '2001:3::/32', '2001:4:112::/48',
                '2001:20::/28', '2001:30::/28'),
        }
        exceptions = [ipaddress.ip_network(value) for value in fallback_exceptions[version]]
    if version == 4:
        ranges = [*ranges, ipaddress.ip_network('100.64.0.0/10')]
    return ranges, exceptions


def _allowed_network(network, settings):
    link_local = ipaddress.ip_network('169.254.0.0/16' if network.version == 4 else 'fe80::/10')
    if network.overlaps(link_local):
        return False
    mapped = ipaddress.ip_network('::ffff:0:0/96') if network.version == 6 else None
    if mapped is not None and network.overlaps(mapped):
        part = network if network.subnet_of(mapped) else mapped
        v4 = ipaddress.ip_network(f'{part.network_address.ipv4_mapped}/{part.prefixlen - 96}', strict=False)
        if not _allowed_network(v4, settings):
            return False
        if network.subnet_of(mapped):
            return True
    if settings.LAB_MODE:
        return True
    if not network.is_global:
        return False
    ranges, exceptions = _special_networks(network.version)
    for special in ranges:
        if mapped is not None and special == mapped:
            continue  # IPv4-mapped ranges were classified as IPv4 above.
        if network.overlaps(special):
            part = network if network.subnet_of(special) else special
            if not any(part.subnet_of(exception) for exception in exceptions):
                return False
    return True


def canonical_target(value, settings):
    """Return the exact canonical target used by protection and session scope."""
    if not valid_text(value, 'target') or any(c.isspace() for c in value) or '\\' in value:
        return None
    try:
        if '/' in value and '://' not in value:
            network = ipaddress.ip_network(value, strict=False)
            return str(network) if _allowed_network(network, settings) else None
        url = None
        if '://' in value:
            url = urlsplit(value)
            if (url.scheme not in ('http', 'https') or url.username is not None or
                    url.password is not None or url.query or url.fragment):
                return None
            if url.port == 0:
                return None
            host = url.hostname
        else:
            host = value
        if not host:
            return None
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            domain = host.encode('idna').decode('ascii').lower().rstrip('.')
            if len(domain) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', x) for x in domain.split('.')):
                return None
            if domain != 'localhost' and '.' not in domain:
                return None
            if re.fullmatch(r'[0-9.]+', domain):
                return None
            host = domain
        if not allowed_target(host, settings)[0]:
            return None
        if url is not None:
            authority = f'[{host}]' if ':' in host else host
            if url.port is not None:
                authority += f':{url.port}'
            return urlunsplit((url.scheme, authority, url.path, '', ''))
        return host
    except (ValueError, UnicodeError):
        return None


def valid_target(value, settings):
    return canonical_target(value, settings) is not None


def validate_setup(payload, defaults, settings):
    errors = {}
    if not isinstance(payload, dict) or set(payload) != SETUP_FIELDS or payload.get('type') != 'configure':
        return None, {'form': ERRORS['form']}
    for field in LIMITS:
        if not valid_text(payload[field], field, empty=field == 'api_key'):
            errors[field] = ERRORS[field]
    if payload['authorized'] is not True:
        errors['authorized'] = ERRORS['authorized']
    if 'api_base' not in errors and not valid_api_base(payload['api_base']):
        errors['api_base'] = ERRORS['api_base']
    target = canonical_target(payload['target'], settings) if 'target' not in errors else None
    if target is None:
        errors['target'] = ERRORS['target']
    key = optional_api_key(payload['api_key']) if 'api_key' not in errors else None
    key = key or defaults.api_key
    if not key:
        errors['api_key'] = ERRORS['api_key']
    if errors:
        return None, errors
    name = payload['model'].strip()
    connection = ModelSpec(model=name if '/' in name else 'openai/' + name,
                           api_base=payload['api_base'].strip().rstrip('/'), api_key=key)
    return SetupResult(target=target, connection=connection), {}


async def run_rich_setup(defaults, settings):
    """Hidden-key fallback. Never read a secret from pipes or batch input."""
    from rich.console import Console
    console = Console()
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None, 2
    values = defaults.public()
    try:
        while True:
            console.print('启动配置 · API Key 仅本次进程使用 · 输入 /quit 退出')
            for field, label in [('api_base', 'API 根地址'), ('model', '模型'), ('target', '目标（例如 example.com）')]:
                answer = input(f'{label} [{values[field]}]: ').strip()
                if answer == '/quit':
                    return None, 0
                values[field] = answer or values[field]
            # getpass refuses accidental pipe entry by the checks above.
            key = getpass.getpass('API Key（留空沿用已有 Key）: ' if defaults.api_key else 'API Key: ')
            authorized = input('确认已获本次目标合法授权？(yes/no): ').strip().lower() in ('yes', 'y', '确认')
            result, errors = validate_setup(dict(type='configure', **{k: values[k] for k in ('api_base', 'model', 'target')},
                                                  api_key=key, authorized=authorized), defaults, settings)
            key = ''
            if result:
                return result, 0
            for message in errors.values():
                console.print(message, markup=False)
    except KeyboardInterrupt:
        return None, 130
    except (EOFError, OSError):
        return None, 0
