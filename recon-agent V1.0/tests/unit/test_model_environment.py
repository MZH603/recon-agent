"""Offline checks for project-scoped primary model environment overrides."""
import asyncio
from types import SimpleNamespace as NS

import pytest
from pydantic import SecretStr

from model.registry import build_provider, resolve_model
from utils.config import Settings


@pytest.fixture
def sdk_calls(monkeypatch):
    calls = []

    async def complete(**kwargs):
        calls.append(kwargs)
        return NS(choices=[NS(message=NS(content='ok', tool_calls=None))],
                  usage=None, model=kwargs['model'])

    monkeypatch.setattr('model.litellm_adapter._import_litellm',
                        lambda: NS(acompletion=complete))
    return calls


def invoke(provider):
    return asyncio.run(provider.complete([]))


def set_connection_environment(monkeypatch):
    monkeypatch.setenv('RECON_MODEL', '  openai/environment-model  ')
    monkeypatch.setenv('RECON_API_BASE', '  https://environment.example/v1  ')
    monkeypatch.setenv('RECON_API_KEY', ' fixture-environment-key ')


@pytest.mark.parametrize('override', [None, 'openai/cli-model'])
def test_environment_connection_precedes_yaml_and_cli_selects_model(
    monkeypatch, sdk_calls, override,
):
    set_connection_environment(monkeypatch)
    monkeypatch.delenv('YAML_API_KEY', raising=False)
    settings = Settings(model={'name': 'openai/yaml-model',
                               'api_base': 'https://yaml.example/v1',
                               'api_key': 'fixture-yaml-key', 'api_key_env': 'YAML_API_KEY',
                               'fallback': []})
    invoke(build_provider(settings, override))
    assert sdk_calls[0]['model'] == (override or 'openai/environment-model')
    assert sdk_calls[0]['api_base'] == 'https://environment.example/v1'
    assert sdk_calls[0]['api_key'] == ' fixture-environment-key '


def test_selected_named_endpoint_gets_environment_connection(monkeypatch, sdk_calls):
    set_connection_environment(monkeypatch)
    settings = Settings(model={'fallback': [], 'custom_endpoints': [
        {'name': 'custom', 'model': 'openai/custom', 'base_url': 'https://custom.example/v1',
         'api_key': 'fixture-endpoint-key', 'api_key_env': 'MISSING_ENDPOINT_KEY'}]})
    invoke(build_provider(settings, 'custom'))
    assert sdk_calls[0]['model'] == 'openai/custom'
    assert sdk_calls[0]['api_base'] == 'https://environment.example/v1'
    assert sdk_calls[0]['api_key'] == ' fixture-environment-key '


def test_fallback_names_and_connections_ignore_primary_environment(monkeypatch, sdk_calls):
    set_connection_environment(monkeypatch)
    monkeypatch.setenv('BACKUP_API_KEY', 'fixture-backup-env')
    settings = Settings(model={'api_key': 'fixture-yaml-key',
                               'api_base': 'https://yaml.example/v1',
                               'fallback': ['claude-3-5-sonnet', 'backup'],
                               'custom_endpoints': [
                                   {'name': 'backup', 'model': 'openai/backup',
                                    'api_base': 'https://backup.example/v1',
                                    'api_key_env': 'BACKUP_API_KEY'}]})
    provider = build_provider(settings)
    for adapter in provider._providers:
        invoke(adapter)
    assert sdk_calls[0]['model'] == 'openai/environment-model'
    assert sdk_calls[1]['model'] == 'claude-3-5-sonnet'
    assert 'api_base' not in sdk_calls[1] and 'api_key' not in sdk_calls[1]
    assert sdk_calls[2]['model'] == 'openai/backup'
    assert sdk_calls[2]['api_base'] == 'https://backup.example/v1'
    assert sdk_calls[2]['api_key'] == 'fixture-backup-env'
    fallback = resolve_model(settings, inherit_primary=False)
    assert fallback.model == settings.model.name
    assert fallback.api_base is None and fallback.api_key is None


@pytest.mark.parametrize('environment', [None, '', ' \t\n '])
@pytest.mark.parametrize('direct_key', [None, 'fixture-yaml-key'])
def test_blank_or_absent_overrides_preserve_yaml(monkeypatch, sdk_calls, environment, direct_key):
    if environment is not None:
        for name in ('RECON_MODEL', 'RECON_API_BASE', 'RECON_API_KEY'):
            monkeypatch.setenv(name, environment)
    monkeypatch.setenv('YAML_API_KEY', 'fixture-yaml-env')
    settings = Settings(model={'name': 'openai/yaml-model',
                               'api_base': 'https://yaml.example/v1',
                               'api_key': direct_key, 'api_key_env': 'YAML_API_KEY',
                               'fallback': []})
    invoke(build_provider(settings))
    assert sdk_calls[0]['model'] == 'openai/yaml-model'
    assert sdk_calls[0]['api_base'] == 'https://yaml.example/v1'
    assert sdk_calls[0]['api_key'] == (direct_key or 'fixture-yaml-env')


@pytest.mark.parametrize('direct_key', [None, 'fixture-yaml-key'])
def test_base_only_override_preserves_existing_key(monkeypatch, sdk_calls, direct_key):
    monkeypatch.setenv('RECON_API_BASE', 'https://environment.example/v1')
    monkeypatch.setenv('YAML_API_KEY', 'fixture-yaml-env')
    settings = Settings(model={'api_key': direct_key, 'api_key_env': 'YAML_API_KEY',
                               'fallback': []})
    invoke(build_provider(settings))
    assert sdk_calls[0]['api_base'] == 'https://environment.example/v1'
    assert sdk_calls[0]['api_key'] == (direct_key or 'fixture-yaml-env')


def test_model_only_environment_selects_named_endpoint_and_preserves_key(monkeypatch, sdk_calls):
    monkeypatch.setenv('RECON_MODEL', ' custom ')
    settings = Settings(model={'api_key': 'fixture-primary-key', 'fallback': [],
                               'custom_endpoints': [
                                   {'name': 'custom', 'model': 'openai/custom',
                                    'base_url': 'https://custom.example/v1',
                                    'api_key': 'fixture-endpoint-key'}]})
    invoke(build_provider(settings))
    assert sdk_calls[0]['model'] == 'openai/custom'
    assert sdk_calls[0]['api_base'] == 'https://custom.example/v1'
    assert sdk_calls[0]['api_key'] == 'fixture-endpoint-key'


def test_unconfigured_connection_preserves_sdk_ambient_credentials(sdk_calls):
    invoke(build_provider(Settings(model={'fallback': []})))
    assert 'api_base' not in sdk_calls[0] and 'api_key' not in sdk_calls[0]


def test_environment_secret_is_masked_and_settings_are_unchanged(monkeypatch):
    set_connection_environment(monkeypatch)
    settings = Settings(model={'name': 'openai/yaml-model', 'api_key': 'fixture-yaml-key',
                               'api_base': 'https://yaml.example/v1', 'fallback': []})
    before = settings.model_copy(deep=True)
    spec = resolve_model(settings)
    assert isinstance(spec.api_key, SecretStr)
    assert spec.api_key.get_secret_value() == ' fixture-environment-key '
    assert settings == before
    for value in (spec, settings):
        for output in (repr(value), str(value.model_dump()), value.model_dump_json()):
            assert 'fixture-environment-key' not in output


def test_missing_fallback_key_does_not_mean_primary_environment_failed(monkeypatch, sdk_calls):
    monkeypatch.setenv('RECON_MODEL', 'openai/deepseek-flash')
    monkeypatch.setenv('RECON_API_BASE', 'https://api.deepseek.com/v1')
    monkeypatch.setenv('RECON_API_KEY', 'fixture-primary-key')
    monkeypatch.delenv('DEEPSEEK_API_KEY', raising=False)
    notices = []
    monkeypatch.setattr('model.registry.warn', notices.append)
    settings = Settings(model={'api_key_env': 'OPENAI_API_KEY',
                               'fallback': ['deepseek-chat'], 'custom_endpoints': [
        {'name': 'deepseek', 'model': 'deepseek-chat',
         'base_url': 'https://api.deepseek.com/v1', 'api_key_env': 'DEEPSEEK_API_KEY'}]})
    invoke(build_provider(settings))
    assert sdk_calls[0]['model'] == 'openai/deepseek-flash'
    assert sdk_calls[0]['api_key'] == 'fixture-primary-key'
    assert len(notices) == 1
    assert '备用模型 deepseek-chat' in notices[0]
    assert '不影响主模型连接配置' in notices[0]
    assert 'fixture-primary-key' not in notices[0]
