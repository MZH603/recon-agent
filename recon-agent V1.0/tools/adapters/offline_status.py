"""Offline inventory describes configuration/readiness without starting programs."""
from pathlib import Path
import shutil


def _executable_status(command, args=()):
    if not command or '{' in command:
        return 'template-executable'
    executable = shutil.which(command)
    if executable is None:
        return 'missing-executable'
    if Path(executable).suffix.lower() in ('.cmd', '.bat'):
        return 'requires-native-executable'
    # Common node/Python absolute script configuration, without importing it.
    if args and not args[0].startswith('-') and Path(args[0]).suffix.lower() in ('.js', '.mjs', '.py'):
        if not Path(args[0]).is_file():
            return 'missing-script'
    return 'executable-found'


def tool_inventory(settings, registry):
    custom = {item.name: item for item in settings.custom_tools if item.enabled}
    entries = []
    for name in registry.names():
        tool = registry.get(name)
        status = 'registered'
        if name in custom:
            config = custom[name]
            if config.kind == 'command':
                status = _executable_status(config.command[0], config.command[1:])
            elif config.kind == 'script':
                status = 'bandit-found' if shutil.which('bandit') else 'requires-bandit'
            elif config.kind == 'shell':
                status = 'manual-hint'
            else:
                status = 'configured-http'
        entries.append({'name': name, 'description': tool.description, 'min_level': tool.min_level,
                        'enabled': True, 'deferred': getattr(tool, 'deferred', False), 'status': status})
    for config in settings.custom_tools:
        if not config.enabled:
            entries.append({'name': config.name, 'description': config.description or config.kind,
                            'min_level': config.min_level, 'enabled': False, 'deferred': config.deferred,
                            'status': 'disabled'})
    for config in settings.mcp_servers:
        status = 'disabled' if not config.enabled else (
            _executable_status(config.command, config.args) if config.transport == 'stdio' else 'configured-http')
        entries.append({'name': 'mcp:' + config.name, 'description': config.transport + ' connector (not connected)',
                        'min_level': config.min_level, 'enabled': config.enabled, 'deferred': config.deferred,
                        'status': status})
    from tools.adapters.extension_inventory import configured_extension_rows
    configured = configured_extension_rows(settings)
    for row in configured:
        if row['id'] == 'extension:search':
            names = ['web_search'] + (['web_get_contents'] if settings.extension_tools.search.provider == 'exa' else [])
        elif row['id'] == 'extension:caido':
            names = ['list_requests', 'view_request', 'list_sitemap']
        else:
            names = [row['name']]
        for name in names:
            existing = next((entry for entry in entries if entry['name'] == name), None)
            if existing is None:
                entries.append(dict(name=name, description=row['kind'], min_level=row['min_level'],
                    enabled=False, deferred=True, status='disabled'))
            else:
                existing['status'] = row['status']
    return entries
