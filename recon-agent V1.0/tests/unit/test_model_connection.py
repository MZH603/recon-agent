"""Offline regression tests for model connection configuration and secret handling."""
import asyncio
from types import SimpleNamespace as NS

import pytest
from pydantic import SecretStr

from model.base import ModelUnavailable
from model.litellm_adapter import LiteLLMAdapter
from model.registry import ModelSpec, build_provider, resolve_model
from utils.config import ModelConfig, Settings


@pytest.fixture
def sdk_calls(monkeypatch):
    calls = []

    async def complete(**kwargs):
        calls.append(kwargs)
        return NS(choices=[NS(message=NS(content='ok', tool_calls=None))],
                  usage=NS(prompt_tokens=3, completion_tokens=4), model=kwargs['model'],
                  _hidden_params={'response_cost': 0.125})

    monkeypatch.setattr('model.litellm_adapter._import_litellm', lambda: NS(acompletion=complete))
    return calls


def invoke(provider):
    return asyncio.run(provider.complete([]))


def test_yaml_connection_reaches_sdk(tmp_path, sdk_calls, monkeypatch):
    monkeypatch.delenv('CONNECTION_API_KEY', raising=False)
    path = tmp_path / 'config.yaml'
    path.write_text('''model:
  name: openai/custom-model
  api_base: https://your-endpoint.example/v1
  api_key: fixture-direct-secret
  api_key_env: CONNECTION_API_KEY
  fallback: []
''', encoding='utf-8')
    settings = Settings.load(path)
    response = invoke(build_provider(settings))
    assert sdk_calls[0]['api_base'] == 'https://your-endpoint.example/v1'
    assert sdk_calls[0]['api_key'] == 'fixture-direct-secret'
    assert sdk_calls[0]['model'] == 'openai/custom-model'
    assert response.token_usage['cost'] == 0.125
    assert settings.model.api_key == SecretStr('fixture-direct-secret')


@pytest.mark.parametrize('environment', [None, 'fixture-env-secret'])
def test_direct_key_precedes_optional_environment(monkeypatch, sdk_calls, environment):
    if environment is None:
        monkeypatch.delenv('CONNECTION_API_KEY', raising=False)
    else:
        monkeypatch.setenv('CONNECTION_API_KEY', environment)
    settings = Settings(model={'api_key': 'fixture-direct-secret',
                               'api_key_env': 'CONNECTION_API_KEY', 'fallback': []})
    invoke(build_provider(settings))
    assert sdk_calls[0]['api_key'] == 'fixture-direct-secret'


@pytest.mark.parametrize('blank', ['', '   ', None])
def test_blank_direct_key_uses_environment(monkeypatch, sdk_calls, blank):
    monkeypatch.setenv('CONNECTION_API_KEY', 'fixture-env-secret')
    settings = Settings(model={'api_key': blank, 'api_key_env': 'CONNECTION_API_KEY', 'fallback': []})
    invoke(build_provider(settings))
    assert sdk_calls[0]['api_key'] == 'fixture-env-secret'


def test_missing_explicit_environment_is_clear_and_makes_no_request(monkeypatch, sdk_calls):
    monkeypatch.delenv('CONNECTION_API_KEY', raising=False)
    settings = Settings(model={'api_key': '', 'api_key_env': 'CONNECTION_API_KEY', 'fallback': []})
    with pytest.raises(ModelUnavailable, match='API Key'):
        build_provider(settings)
    assert sdk_calls == []


def test_no_explicit_key_keeps_sdk_ambient_credentials(sdk_calls):
    invoke(build_provider(Settings(model={'api_key': '', 'fallback': []})))
    assert 'api_key' not in sdk_calls[0]


@pytest.mark.parametrize('base_field', ['base_url', 'api_base'])
@pytest.mark.parametrize('direct', [False, True])
def test_named_endpoint_uses_own_connection(monkeypatch, sdk_calls, base_field, direct):
    monkeypatch.setenv('ENDPOINT_API_KEY', 'fixture-endpoint-env')
    endpoint = {'name': 'custom', 'model': 'openai/custom', base_field: 'https://custom.example/v1',
                'api_key_env': 'ENDPOINT_API_KEY'}
    if direct:
        endpoint['api_key'] = 'fixture-endpoint-direct'
    settings = Settings(model={'api_base': 'https://primary.example/v1', 'api_key': 'fixture-primary',
                               'api_key_env': 'PRIMARY_API_KEY', 'fallback': [],
                               'custom_endpoints': [endpoint]})
    invoke(build_provider(settings, 'custom'))
    assert sdk_calls[0]['api_base'] == 'https://custom.example/v1'
    assert sdk_calls[0]['api_key'] == ('fixture-endpoint-direct' if direct else 'fixture-endpoint-env')
    assert sdk_calls[0]['model'] == 'openai/custom'


def test_cli_model_override_reuses_primary_connection(sdk_calls):
    settings = Settings(model={'api_base': 'https://primary.example/v1', 'api_key': 'fixture-primary',
                               'fallback': []})
    invoke(build_provider(settings, 'openai/replacement'))
    assert sdk_calls[0]['model'] == 'openai/replacement'
    assert sdk_calls[0]['api_base'] == 'https://primary.example/v1'
    assert sdk_calls[0]['api_key'] == 'fixture-primary'


def test_fallback_connections_do_not_inherit_primary_secrets(monkeypatch, sdk_calls):
    monkeypatch.setenv('PRIMARY_API_KEY', 'fixture-primary-env')
    settings = Settings(model={'api_base': 'https://primary.example/v1', 'api_key': 'fixture-primary',
                               'api_key_env': 'PRIMARY_API_KEY',
                               'fallback': ['claude-3-5-sonnet', 'secondary'],
                               'custom_endpoints': [{'name': 'secondary', 'model': 'openai/secondary',
                                                    'base_url': 'https://secondary.example/v1'}]})
    provider = build_provider(settings)
    for adapter in provider._providers:
        invoke(adapter)
    assert sdk_calls[0]['api_key'] == 'fixture-primary'
    assert 'api_key' not in sdk_calls[1] and 'api_base' not in sdk_calls[1]
    assert 'api_key' not in sdk_calls[2]
    assert sdk_calls[2]['api_base'] == 'https://secondary.example/v1'


def test_named_primary_has_no_inherited_credentials(sdk_calls):
    settings = Settings(model={'name': 'custom', 'api_key': 'fixture-primary', 'fallback': [],
                               'custom_endpoints': [{'name': 'custom', 'model': 'openai/custom'}]})
    invoke(build_provider(settings))
    assert 'api_key' not in sdk_calls[0]


def test_secret_safe_representations_and_assignment():
    settings = Settings(model={'api_base': 'https://primary.example/v1', 'api_key': 'fixture-primary',
                               'api_key_env': 'PRIMARY_API_KEY'})
    settings.model.custom_endpoints = [{'name': 'custom', 'base_url': 'https://custom.example/v1',
                                        'api_key': 'fixture-endpoint'}]
    spec = resolve_model(settings, 'custom')
    for value in [settings, settings.model, spec, ModelSpec(model='m', api_key='fixture-primary')]:
        for output in [repr(value), str(value.model_dump()), value.model_dump_json()]:
            assert 'fixture-primary' not in output
            assert 'fixture-endpoint' not in output
    assert isinstance(settings.model.custom_endpoints[0]['api_key'], SecretStr)
    assert isinstance(spec.api_key, SecretStr)
    restored = ModelConfig.model_validate_json(settings.model.model_dump_json())
    assert restored.api_base == settings.model.api_base
    assert restored.api_key_env == settings.model.api_key_env
    assert restored.custom_endpoints[0]['base_url'] == 'https://custom.example/v1'


def test_adapter_keeps_old_positional_signature_and_masked_key(sdk_calls):
    adapter = LiteLLMAdapter('openai/m', 'https://custom.example/v1', None, 0, 0, 10,
                            api_key='fixture-adapter-secret')
    assert isinstance(adapter.api_key, SecretStr)
    assert 'fixture-adapter-secret' not in repr(vars(adapter))
    invoke(adapter)
    assert sdk_calls[0]['api_key'] == 'fixture-adapter-secret'
    assert sdk_calls[0]['timeout'] == 10


@pytest.mark.parametrize('error_type', [ValueError, ModelUnavailable])
def test_sdk_exception_body_never_leaks_key(monkeypatch, error_type):
    async def complete(**kwargs):
        raise error_type('response body echoed fixture-error-secret')
    monkeypatch.setattr('model.litellm_adapter._import_litellm', lambda: NS(acompletion=complete))
    with pytest.raises(ModelUnavailable) as caught:
        invoke(LiteLLMAdapter('openai/m', max_retries=0, api_key='fixture-error-secret'))
    assert 'fixture-error-secret' not in str(caught.value)

@pytest.mark.parametrize('config', [{'api_key': 123}, {'custom_endpoints': [{'api_key': 123}]}])
def test_malformed_credentials_report_validation_error(config):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        ModelConfig(**config)


def test_blank_secret_string_uses_environment(monkeypatch, sdk_calls):
    monkeypatch.setenv('CONNECTION_API_KEY', 'fixture-env-secret')
    settings = Settings(model={'api_key': SecretStr('   '),
                               'api_key_env': 'CONNECTION_API_KEY', 'fallback': []})
    invoke(build_provider(settings))
    assert sdk_calls[0]['api_key'] == 'fixture-env-secret'


def test_sdk_model_unavailable_is_sanitized_without_retry(monkeypatch):
    calls = []

    async def complete(**kwargs):
        calls.append(1)
        raise ModelUnavailable('body echoed fixture-error-secret')

    async def no_sleep(_):
        pass

    monkeypatch.setattr('model.litellm_adapter._import_litellm', lambda: NS(acompletion=complete))
    monkeypatch.setattr('model.litellm_adapter.asyncio.sleep', no_sleep)
    with pytest.raises(ModelUnavailable) as caught:
        invoke(LiteLLMAdapter('openai/m', max_retries=2, api_key='fixture-error-secret'))
    assert calls == [1]
    assert 'fixture-error-secret' not in str(caught.value)
