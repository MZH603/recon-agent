"""Launcher configuration stays local, authenticated and idle until confirmed."""
import asyncio
import json

import pytest

KEY = 'dummy-launcher-secret-9384'


@pytest.fixture(autouse=True)
def isolated_launcher_environment(monkeypatch, tmp_path):
    for name in ('RECON_MODEL', 'RECON_API_BASE', 'RECON_API_KEY'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr('platforms.paths.get_config_dir', lambda: tmp_path)
    monkeypatch.setattr('utils.logger._console', None)
    monkeypatch.setattr('utils.logger._stderr_mode', False)


def test_defaults_and_secret_store(tmp_path, monkeypatch):
    from cli.launcher import prefill, validate_setup, save_defaults, load_defaults
    from utils.config import Settings
    settings = Settings(model={'name': 'yaml-model', 'api_base': 'https://yaml.test/v1', 'api_key': KEY})
    monkeypatch.setenv('RECON_MODEL', 'env-model')
    monkeypatch.setenv('RECON_API_BASE', 'https://env.test/v1')
    save_defaults({'api_base': 'https://saved.test/v1', 'model': 'saved', 'target': 'example.net'}, tmp_path)
    defaults = prefill(settings, model='explicit', target='example.org', config_dir=tmp_path)
    assert defaults.public() == {'api_base': 'https://env.test/v1', 'model': 'explicit', 'target': 'example.org', 'key_available': True}
    assert KEY not in repr(defaults)
    result, errors = validate_setup(dict(type='configure', api_base='https://new.test/v1', model='new-model', target='example.org', api_key='', authorized=True), defaults, settings)
    assert not errors
    assert result.connection.model == 'openai/new-model'
    assert result.connection.api_key.get_secret_value() == KEY
    assert KEY not in repr(result) and KEY not in result.model_dump_json()
    save_defaults(result.public(), tmp_path)
    saved = json.loads((tmp_path / 'launcher.json').read_text())
    assert set(saved) == {'api_base', 'model', 'target'}
    assert KEY not in (tmp_path / 'launcher.json').read_text()
    (tmp_path / 'launcher.json').write_text(KEY)
    assert load_defaults(tmp_path) == {}


def test_first_target_empty_and_environment_key_only_in_python(tmp_path, monkeypatch):
    from cli.launcher import prefill
    from utils.config import Settings
    monkeypatch.setenv('RECON_API_KEY', KEY)
    defaults = prefill(Settings(), config_dir=tmp_path)
    assert defaults.public()['target'] == ''
    assert defaults.public()['key_available'] is True
    assert KEY not in json.dumps(defaults.public())


@pytest.mark.parametrize('updates,field', [
    ({'authorized': False}, 'authorized'), ({'authorized': 1}, 'authorized'),
    ({'api_base': 'https://user:password@api.test/v1'}, 'api_base'),
    ({'api_base': 'https://@api.test/v1'}, 'api_base'),
    ({'api_base': 'https://api.test/v1?key=secret'}, 'api_base'),
    ({'api_base': 'https://api.test/v1#fragment'}, 'api_base'),
    ({'api_base': 'https://api.test/v1/chat/completions'}, 'api_base'),
    ({'api_base': 'file:///tmp'}, 'api_base'), ({'target': 'invalid target'}, 'target'),
    ({'target': 'https://@example.org/'}, 'target'),
    ({'target': 'agency.gov'}, 'target'), ({'target': '127.0.0.1'}, 'target'),
    ({'model': ''}, 'model'), ({'api_key': ''}, 'api_key'),
    ({'model': KEY + '\n'}, 'model'), ({'extra': KEY}, 'form'),
])
def test_fixed_validation_errors(tmp_path, updates, field):
    from cli.launcher import prefill, validate_setup
    from utils.config import Settings
    settings = Settings()
    payload = dict(type='configure', api_base='https://api.test/v1', model='openai/model', target='example.org', api_key=KEY, authorized=True)
    payload.update(updates)
    result, errors = validate_setup(payload, prefill(settings, config_dir=tmp_path), settings)
    assert result is None and field in errors
    assert KEY not in json.dumps(errors)


def test_lab_target_and_explicit_primary_not_overwritten(tmp_path, monkeypatch):
    from cli.launcher import prefill, validate_setup
    from model.registry import build_provider, resolve_model
    from utils.config import Settings
    settings = Settings(LAB_MODE=True, model={'fallback': []})
    monkeypatch.setenv('RECON_MODEL', 'old-model')
    monkeypatch.setenv('RECON_API_BASE', 'https://old.test/v1')
    monkeypatch.setenv('RECON_API_KEY', 'old-key')
    result, errors = validate_setup(dict(type='configure', api_base='https://new.test/v1', model='new-model', target='127.0.0.1', api_key=KEY, authorized=True), prefill(settings, config_dir=tmp_path), settings)
    assert not errors
    assert resolve_model(settings).model == 'old-model'
    calls = []
    monkeypatch.setattr('model.registry.LiteLLMAdapter', lambda **kwargs: calls.append(kwargs))
    build_provider(settings, connection_override=result.connection)
    assert calls[0]['model'] == 'openai/new-model'
    assert calls[0]['api_base'] == 'https://new.test/v1'
    assert calls[0]['api_key'].get_secret_value() == KEY


def test_authenticated_setup_tcp_rejects_runtime_and_bad_schema():
    from cli.tui_bridge import TuiBridge, ProtocolError
    async def scenario():
        async with TuiBridge() as bridge:
            reader, writer = await asyncio.open_connection('127.0.0.1', bridge.port)
            def send(value): writer.write((json.dumps(value)+'\n').encode())
            send({'type': 'hello', 'token': bridge.token})
            await bridge.wait_connected()
            payload = dict(type='configure', api_base='https://api.test/v1', model='model', target='example.org', api_key=KEY, authorized=True)
            send(payload)
            assert await bridge.receive_setup() == payload
            send(dict(payload, authorized=1))
            with pytest.raises(ProtocolError): await bridge.receive_setup()
            send(payload)
            with pytest.raises(ProtocolError): await bridge.receive()
            writer.close()
            await writer.wait_closed()
    asyncio.run(scenario())


def test_setup_retry_and_accept_before_session(tmp_path):
    from cli.tui_bridge import TuiBridge, read_frame
    from cli.tui_setup import serve_setup
    from cli.launcher import prefill
    from utils.config import Settings
    async def scenario():
        settings = Settings()
        async with TuiBridge() as bridge:
            reader, writer = await asyncio.open_connection('127.0.0.1', bridge.port)
            def send(value): writer.write((json.dumps(value)+'\n').encode())
            send({'type':'hello', 'token':bridge.token})
            await bridge.wait_connected()
            task = asyncio.create_task(serve_setup(bridge, prefill(settings, config_dir=tmp_path), settings))
            state = await read_frame(reader)
            assert state['type'] == 'defaults' and KEY not in json.dumps(state)
            payload = dict(type='configure', api_base='https://api.test/v1', model='model', target='example.org', api_key=KEY, authorized=False)
            send(payload)
            assert (await read_frame(reader))['type'] == 'errors'
            send(dict(payload, authorized=True))
            assert (await read_frame(reader)) == {'type':'accepted'}
            result, code = await task
            assert code == 0 and result.connection.api_key.get_secret_value() == KEY
            writer.close(); await writer.wait_closed()
    asyncio.run(scenario())


def test_bare_and_auth_cli_use_context_and_idle_session(monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from cli.main import app
    from cli.launcher import prefill, validate_setup
    from utils.config import Settings
    settings = Settings()
    result, _ = validate_setup(dict(type='configure', api_base='https://api.test/v1', model='model', target='example.org', api_key=KEY, authorized=True), prefill(settings, config_dir=tmp_path), settings)
    import cli.main as main
    def tty_settings(*args):
        monkeypatch.setattr(main.sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr(main.sys.stdout, 'isatty', lambda: True)
        return settings
    monkeypatch.setattr(main, '_settings_with', tty_settings)
    monkeypatch.setattr('cli.launcher.get_config_dir', lambda: tmp_path)
    monkeypatch.setenv('TERM', 'xterm')
    monkeypatch.setattr('cli.tui_bridge.tui_available', lambda: (False, 'fixture'))
    calls = []
    async def setup(*args, **kwargs): return result, 0
    async def session(**kwargs): calls.append(kwargs); return 0
    monkeypatch.setattr('cli.launcher.run_rich_setup', setup)
    monkeypatch.setattr('cli.session.run_session', session)
    for args in ([], ['--auth', '--ui', 'rich']):
        invocation = CliRunner().invoke(app, args)
        assert invocation.exit_code == 0, invocation.output
        assert calls[-1]['requested_level'] == 0
        assert calls[-1]['connection_override'] is result.connection
    # Passing existing options must retain the old missing-target behavior.
    assert CliRunner().invoke(app, ['--session']).exit_code == 2
    assert CliRunner().invoke(app, ['--auth', '--batch']).exit_code == 2
    assert CliRunner().invoke(app, ['--auth', '--mcp']).exit_code == 2


def test_rich_never_reads_key_without_tty(monkeypatch, tmp_path):
    from cli.launcher import run_rich_setup, prefill
    from utils.config import Settings
    monkeypatch.setattr('cli.launcher.sys.stdin.isatty', lambda: False)
    monkeypatch.setattr('builtins.input', lambda *args: pytest.fail('must not prompt'))
    assert asyncio.run(run_rich_setup(prefill(Settings(), config_dir=tmp_path), Settings())) == (None, 2)


def test_cli_python_interrupt_exits_130(monkeypatch):
    from typer.testing import CliRunner
    import cli.main as main
    def interrupt(coroutine):
        coroutine.close()
        raise KeyboardInterrupt
    monkeypatch.setattr(main.asyncio, 'run', interrupt)
    assert CliRunner().invoke(main.app, ['--auth']).exit_code == 130


@pytest.mark.parametrize('mode', ['eof', 'quit', 'cancel', 'accepted', 'accepted-cancel', 'accepted-quit', 'no-connect'])
def test_real_setup_child_is_reaped_on_all_paths(tmp_path, monkeypatch, mode):
    """Actual Node child and TCP IPC; no models, tools, runtime or database."""
    import shutil
    from cli import tui_setup
    from cli.launcher import prefill
    from utils.config import Settings
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    entry = tmp_path / 'setup-app.mjs'
    payload = dict(type='configure', api_base='https://api.test/v1', model='model', target='example.org', api_key=KEY, authorized=True)
    command = payload if mode.startswith('accepted') else {'type':mode}
    entry.write_text("""
import net from 'node:net';
const socket=net.createConnection({host:'127.0.0.1',port:Number(process.env.RECON_TUI_PORT)});
socket.on('error',()=>{});
socket.on('connect',()=>{
 socket.write(JSON.stringify({type:'hello',token:process.env.RECON_TUI_TOKEN})+'\\n');
});
socket.once('data',()=>{
 COMMAND
 if(MODE.startsWith('accepted'))socket.once('data',()=>{
  if(MODE==='accepted-quit'){
   socket.write(JSON.stringify({type:'quit'})+'\\n');socket.end();
   socket.on('close',()=>process.exit(0));
  }else process.exit(MODE==='accepted-cancel'?130:0);
 });
});
// Intentionally keep the child alive to exercise force-kill and reap after IPC.
setInterval(()=>{},1000);
""".replace('MODE', json.dumps(mode)).replace('COMMAND', "socket.end();" if mode == 'eof' else
             "socket.write(" + json.dumps(json.dumps(command)+'\n') + ");") if mode != 'no-connect' else 'setInterval(()=>{},1000);', encoding='utf-8')
    monkeypatch.setattr(tui_setup, 'TUI_DIR', tmp_path)
    monkeypatch.setattr(tui_setup, 'tui_available', lambda: (True, ''))
    original_spawn = asyncio.create_subprocess_exec
    children = []
    async def spawn(*args, **kwargs):
        assert KEY not in repr(args) and KEY not in repr(kwargs.get('env'))
        child = await original_spawn(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(asyncio, 'create_subprocess_exec', spawn)
    original_close = tui_setup.close_child
    async def close(child): await original_close(child, timeout=0.05)
    monkeypatch.setattr(tui_setup, 'close_child', close)
    if mode == 'no-connect':
        original_connected = tui_setup.TuiBridge.wait_connected
        async def connect(bridge): await original_connected(bridge, timeout=0.05)
        monkeypatch.setattr(tui_setup.TuiBridge, 'wait_connected', connect)
    settings = Settings()
    result, code = asyncio.run(tui_setup.run_tui_setup(prefill(settings, config_dir=tmp_path), settings))
    assert code == {'eof':2, 'quit':0, 'cancel':130, 'accepted':0, 'accepted-cancel':130, 'accepted-quit':0, 'no-connect':2}[mode]
    assert bool(result) == (mode == 'accepted')
    assert len(children) == 1 and children[0].returncode is not None


def test_noninteractive_cli_never_opens_setup(monkeypatch):
    from typer.testing import CliRunner
    from cli.main import app
    async def forbidden(*args, **kwargs): pytest.fail('setup must not open')
    monkeypatch.setattr('cli.launcher.run_rich_setup', forbidden)
    monkeypatch.setattr('cli.tui_setup.run_tui_setup', forbidden)
    for arguments in ([], ['--auth'], ['--auth', '--batch']):
        result = CliRunner().invoke(app, arguments)
        assert result.exit_code == 2
        assert '交互终端' in result.output


@pytest.mark.parametrize('target', ['agency.ｇｏｖ', 'agency。gov', 'https://agency。gov/',
                                  '8.0.0.0/6', '8.0.0.0/5', '100.0.0.0/8', '2000::/3'])
def test_canonical_protected_domain_and_entire_cidr_are_rejected(tmp_path, target):
    from cli.launcher import prefill, validate_setup
    from utils.config import Settings
    settings = Settings()
    result, errors = validate_setup(dict(type='configure', api_base='https://api.test/v1', model='model', target=target, api_key=KEY, authorized=True), prefill(settings, config_dir=tmp_path), settings)
    assert result is None and 'target' in errors


@pytest.mark.parametrize('target,canonical', [
    ('例子.example.org', 'xn--fsqu00a.example.org'),
    ('Example。ORG.', 'example.org'),
    ('https://例子.example.org:8443/path', 'https://xn--fsqu00a.example.org:8443/path'),
])
def test_confirmed_target_uses_same_canonical_host_as_protection(tmp_path, target, canonical):
    from cli.launcher import prefill, validate_setup
    from utils.config import Settings
    settings = Settings()
    result, errors = validate_setup(dict(type='configure', api_base='https://api.test/v1', model='model', target=target, api_key=KEY, authorized=True), prefill(settings, config_dir=tmp_path), settings)
    assert not errors and result.target == canonical


@pytest.mark.parametrize('target,allowed', [('8.0.0.0/6', True), ('100.0.0.0/8', True),
                                         ('168.0.0.0/6', False), ('fe00::/7', False)])
def test_lab_cidr_unlocks_private_but_never_link_local(tmp_path, target, allowed):
    from cli.launcher import prefill, validate_setup
    from utils.config import Settings
    settings = Settings(LAB_MODE=True)
    result, errors = validate_setup(dict(type='configure', api_base='https://api.test/v1', model='model', target=target, api_key=KEY, authorized=True), prefill(settings, config_dir=tmp_path), settings)
    assert bool(result) is allowed


@pytest.mark.parametrize('target', ['8.8.8.0/24', '192.0.0.9/32', '192.0.0.10/32',
                                  '2001:4860::/32', '2001:1::1/128', '2001:3::/32',
                                  '::ffff:8.8.8.0/120'])
def test_cidr_preserves_globally_routable_special_exceptions(tmp_path, target):
    from cli.launcher import prefill, validate_setup
    from utils.config import Settings
    settings = Settings()
    result, errors = validate_setup(dict(type='configure', api_base='https://api.test/v1', model='model', target=target, api_key=KEY, authorized=True), prefill(settings, config_dir=tmp_path), settings)
    assert result is not None and not errors


@pytest.mark.parametrize('target,allowed', [('8.0.0.0/6', False), ('192.0.0.9/32', True),
                                         ('2000::/3', False), ('2001:3::/32', True)])
def test_network_registry_fallback_retains_protection_and_global_exceptions(monkeypatch, target, allowed):
    import ipaddress
    from types import SimpleNamespace
    from cli.launcher import _allowed_network
    from utils.config import Settings
    network = ipaddress.ip_network(target)
    # Classification still uses real stdlib Address/Network objects. Only the
    # optional internal registry accessor is absent, as on a changed runtime.
    monkeypatch.setattr('cli.launcher.ipaddress.ip_address', lambda value: SimpleNamespace())
    assert _allowed_network(network, Settings()) is allowed
