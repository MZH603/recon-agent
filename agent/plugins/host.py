"""Validate a plugin graph before registering tools; start only on session entry."""
from __future__ import annotations

import asyncio
from importlib import import_module, metadata, util
from pathlib import Path

from pydantic import ValidationError

from agent.plugins.api import PluginManifest


class PluginHost:
    ENTRY_POINT_GROUP = 'recon_agent.plugins'

    def __init__(self, registry):
        self.registry = registry
        self._providers = []
        self._started = []
        self._closed = False
        self._active = False
        self._remaining_names = None
        self._lifecycle_lock = asyncio.Lock()

    @property
    def plugin_ids(self) -> tuple[str, ...]:
        return tuple(provider.manifest.id for provider in self._providers)

    @property
    def context_providers(self):
        return tuple(provider for provider in self._providers
                     if 'context' in provider.manifest.capabilities)

    @property
    def compaction_policy(self):
        return next((provider for provider in self._providers
                     if 'compaction' in provider.manifest.capabilities), None)

    def register_tool(self, tool):
        if self._remaining_names is None:
            raise RuntimeError('Tools can only be registered during provider registration')
        if tool.name not in self._remaining_names:
            raise ValueError(f'Plugin registered undeclared tool name: {tool.name}')
        self.registry.register(tool, replace=False)
        self._remaining_names.remove(tool.name)

    def load_enabled(self, settings, *, builtin=None, builtins=()):
        entries = {entry.name: entry for entry in sorted(
            metadata.entry_points(group=self.ENTRY_POINT_GROUP), key=lambda entry: entry.name)}
        providers = []
        for reference in settings.plugins:
            if reference.module:
                provider = getattr(import_module(reference.module), 'plugin')
            elif reference.path:
                path = Path(reference.path).expanduser().resolve(strict=True)
                if path.suffix != '.py' or not path.is_file():
                    raise ValueError(f'Plugin path must be a Python file: {path}')
                spec = util.spec_from_file_location(f'_recon_plugin_{reference.id.replace("-", "_")}', path)
                if spec is None or spec.loader is None:
                    raise ValueError(f'Cannot load plugin file: {path}')
                module = util.module_from_spec(spec)
                spec.loader.exec_module(module)
                provider = getattr(module, 'plugin')
            else:
                entry = entries.get(reference.entry_point or reference.id)
                if entry is None:
                    raise ValueError(f'Plugin entry point missing: {reference.id}')
                provider = entry.load()
            if isinstance(provider, type):
                provider = provider()
            if provider.manifest.id != reference.id:
                raise ValueError(f'Plugin ID mismatch: {reference.id}')
            providers.append((provider, reference.config))
        self.load(([(builtin, {})] if builtin is not None else []) +
                  [(provider, {}) for provider in builtins] + providers)

    def load(self, providers):
        """Register idle tools. Providers must acquire resources only in start()."""
        if self._providers:
            raise ValueError('Plugins already loaded')
        by_id = {}
        configs = {}
        for provider, raw_config in providers:
            manifest = getattr(provider, 'manifest', None)
            if not isinstance(manifest, PluginManifest):
                raise ValueError('Plugin requires a valid manifest')
            methods = ('register', 'start', 'close')
            if 'tools' in manifest.capabilities:
                methods += ('describe_tool_names',)
            if 'context' in manifest.capabilities:
                methods += ('collect',)
            if 'compaction' in manifest.capabilities:
                methods += ('removal_order',)
            for method in methods:
                if not callable(getattr(provider, method, None)):
                    raise ValueError(f'Plugin {manifest.id} requires {method}()')
            if 'context' in manifest.capabilities and type(getattr(provider, 'required', None)) is not bool:
                raise ValueError(f'Context plugin {manifest.id} requires a boolean required flag')
            if manifest.id in by_id:
                raise ValueError(f'Duplicate plugin ID: {manifest.id}')
            by_id[manifest.id] = provider
            try:
                configs[manifest.id] = (manifest.config_model.model_validate(raw_config)
                    if manifest.config_model else dict(raw_config))
            except (ValidationError, TypeError, ValueError) as exc:
                raise ValueError(f'Invalid config for plugin {manifest.id}: {exc}') from exc
        for ident, provider in by_id.items():
            for dependency in provider.manifest.dependencies:
                if dependency not in by_id:
                    raise ValueError(f'Plugin {ident} requires missing dependency {dependency}')
        compactors = [ident for ident, provider in by_id.items()
                      if 'compaction' in provider.manifest.capabilities]
        if len(compactors) > 1:
            raise ValueError(f'Only one compaction policy may be enabled: {compactors}')
        ordered = []
        visiting = set()
        visited = set()
        def visit(ident):
            if ident in visiting:
                raise ValueError(f'Plugin dependency cycle at {ident}')
            if ident in visited:
                return
            visiting.add(ident)
            for dependency in by_id[ident].manifest.dependencies:
                visit(dependency)
            visiting.remove(ident)
            visited.add(ident)
            ordered.append(by_id[ident])
        for ident in by_id:
            visit(ident)
        declarations = {}
        claimed = set(self.registry.names()) | {
            'ask_user', 'update_plan', 'finish_task', 'recon_safety_policy'}
        for provider in ordered:
            ident = provider.manifest.id
            names = (tuple(provider.describe_tool_names(configs[ident]))
                     if 'tools' in provider.manifest.capabilities else ())
            if any(not isinstance(name, str) or not name for name in names):
                raise ValueError(f'Invalid tool name declaration for {ident}')
            for name in names:
                if name in claimed:
                    raise ValueError(f'Tool name collision: {name}')
                claimed.add(name)
            declarations[ident] = set(names)
        previous = dict(self.registry._tools)
        try:
            for provider in ordered:
                ident = provider.manifest.id
                self._remaining_names = declarations[ident].copy()
                before = dict(self.registry._tools)
                try:
                    running = asyncio.get_running_loop()
                except RuntimeError:
                    running = None
                tasks_before = asyncio.all_tasks(running) if running else set()
                try:
                    provider.register(self, configs[ident])
                finally:
                    if running is not None:
                        new_tasks = asyncio.all_tasks(running) - tasks_before
                        for task in new_tasks:
                            task.cancel()
                        if new_tasks:
                            raise ValueError(f'Plugin {ident} started external work during register')
                actual = set(self.registry._tools) - set(before)
                if actual != declarations[ident] or any(
                    self.registry._tools[name] is not tool for name, tool in before.items()):
                    raise ValueError(f'Plugin {ident} registered undeclared or replaced tool names')
                if self._remaining_names:
                    raise ValueError(f'Plugin {ident} did not register declared tools: {sorted(self._remaining_names)}')
        except BaseException:
            self.registry._tools = previous
            raise
        finally:
            self._remaining_names = None
        self._providers = ordered

    async def start(self, session_view):
        async with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError('Plugin host is closed')
            if self._active:
                return
            try:
                for provider in self._providers:
                    self._started.append(provider)
                    await provider.start(session_view)
                self._active = True
            except BaseException:
                try:
                    await self._close_started()
                except BaseException:
                    pass  # Preserve the startup error after best-effort cleanup.
                raise

    async def close(self):
        async with self._lifecycle_lock:
            await self._close_started()

    async def _close_started(self):
        if self._closed:
            return
        self._closed = True
        first_error = None
        for provider in reversed(self._started):
            try:
                await provider.close()
            except BaseException as exc:
                first_error = first_error or exc
        self._started.clear()
        if first_error:
            raise first_error
