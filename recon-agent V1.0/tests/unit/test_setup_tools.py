"""Optional auth tool selections remain offline and process-local."""
import asyncio
import json

import pytest

from cli.launcher import prefill, validate_setup
from utils.config import Settings

KEY = "dummy-auth-tools-key"


def payload(**updates):
    return dict(type="configure", api_base="https://api.test/v1", model="model",
                target="example.org", api_key=KEY, authorized=True, **updates)


@pytest.fixture
def profile(tmp_path):
    path = tmp_path / "tools.yaml"
    path.write_text("""custom_tools:
  - name: optional_http
    kind: http
    enabled: false
    url: 'https://{target}/api/status'
  - name: optional_hint
    kind: shell
    enabled: true
    command: [curl, '--head', 'https://{target}']
mcp_servers:
  - name: browser
    enabled: false
    command: node
    args: [missing-browser-cli.js]
    allowed_tools: [browser_navigate]
    target_fields: {browser_navigate: [url]}
""", encoding="utf-8")
    return path


def test_skip_preserves_existing_settings_and_saved_fields(tmp_path):
    settings = Settings(custom_tools=[dict(name="existing", kind="shell", command=["echo"])])
    result, errors = validate_setup(payload(), prefill(settings, config_dir=tmp_path), settings)
    assert not errors
    assert result.settings_override is None
    assert set(result.public()) == {"api_base", "model", "target"}


def test_explicit_selection_activates_disabled_configs_without_mutating_base(tmp_path, profile):
    settings = Settings(LAB_MODE=True, model={"api_key": KEY})
    result, errors = validate_setup(payload(tools_config=str(profile), selected_tools=["custom:optional_http", "mcp:browser"]),
                                   prefill(settings, config_dir=tmp_path), settings)
    assert not errors
    chosen = result.settings_override
    assert [c.enabled for c in chosen.custom_tools] == [True, False]
    assert chosen.mcp_servers[0].enabled is True
    assert chosen.LAB_MODE and chosen.GATE_PER_STEP_CONFIRM == settings.GATE_PER_STEP_CONFIRM
    assert chosen.model.api_key.get_secret_value() == KEY
    assert settings.custom_tools == [] and settings.mcp_servers == []
    assert KEY not in result.model_dump_json() and "optional_http" not in result.model_dump_json()


def test_empty_selection_disables_extensions_but_retains_builtin_limits(tmp_path, profile):
    settings = Settings(API_RECON_MAX_REQUESTS=3)
    result, errors = validate_setup(payload(tools_config=str(profile), selected_tools=[]), prefill(settings, config_dir=tmp_path), settings)
    assert not errors
    assert not any(c.enabled for c in result.settings_override.custom_tools + result.settings_override.mcp_servers)
    assert result.settings_override.API_RECON_MAX_REQUESTS == 3


@pytest.mark.parametrize("optional", [
    {"tools_config": "missing.yaml", "selected_tools": []},
    {"tools_config": "", "selected_tools": ["custom:unknown"]},
    {"tools_config": "", "selected_tools": ["x", "x"]},
    {"tools_config": "", "selected_tools": "all"},
    {"tools_config": "", "selected_tools": [1]},
    {"tools_config": "", "selected_tools": ["x"] * 101},
    {"tools_config": "bad\npath", "selected_tools": []},
    {"tools_config": "x" * 2049, "selected_tools": []},
    {"tools_config": ""}, {"selected_tools": []},
])
def test_invalid_optional_fields_are_recoverable_fixed_errors(tmp_path, optional):
    settings = Settings()
    result, errors = validate_setup(payload(**optional), prefill(settings, config_dir=tmp_path), settings)
    assert result is None and "tools_config" in errors
    assert KEY not in json.dumps(errors)
    # Clearing the optional fields must allow entering without a file.
    assert validate_setup(payload(), prefill(settings, config_dir=tmp_path), settings)[0]


def test_profile_cannot_override_gates_or_replace_builtin(tmp_path):
    settings = Settings()
    defaults = prefill(settings, config_dir=tmp_path)
    path = tmp_path / "bad.yaml"
    for source, selection in [("LAB_MODE: true", []),
                              ("custom_tools: [{name: dns_query, kind: shell, command: [echo]}]", ["custom:dns_query"])]:
        path.write_text(source, encoding="utf-8")
        result, errors = validate_setup(payload(tools_config=str(path), selected_tools=selection), defaults, settings)
        assert result is None and "tools_config" in errors


def test_preview_reports_readiness_without_running_or_exposing_secrets(tmp_path, profile, monkeypatch):
    from cli.setup_tools import inspect_tools, default_tool_options
    def forbidden(*args, **kwargs): pytest.fail("auth preview must not start a process or network request")
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("asyncio.create_subprocess_exec", forbidden)
    settings = Settings(model={"api_key": KEY})
    preview = inspect_tools(settings, str(profile))
    assert [row["id"] for row in preview["tools"]] == ["custom:optional_http", "custom:optional_hint", "mcp:browser"]
    assert preview["tools"][2]["status"] in ("missing-script", "missing-executable")
    assert "command" not in json.dumps(preview) and KEY not in json.dumps(preview)
    initial = default_tool_options(settings)
    assert initial["tools"] and all(not row["enabled"] for row in initial["tools"])
    assert initial["tools_config"].endswith("tool-integrations.example.yaml")


def test_profile_limits_and_duplicate_ids_are_rejected(tmp_path, profile):
    from cli.setup_tools import inspect_tools
    path = tmp_path / "large.yaml"
    path.write_bytes(b" " * (262144 + 1))
    with pytest.raises(ValueError): inspect_tools(Settings(), str(path))
    path.write_text("custom_tools: [{name: same, kind: shell, command: [echo]}, {name: same, kind: shell, command: [echo]}]", encoding="utf-8")
    with pytest.raises(ValueError): inspect_tools(Settings(), str(path))


def test_tcp_preview_retry_then_selection_without_secret_frames(tmp_path, profile):
    from cli.tui_bridge import TuiBridge, read_frame
    from cli.tui_setup import serve_setup
    async def scenario():
        settings = Settings()
        async with TuiBridge() as bridge:
            reader, writer = await asyncio.open_connection("127.0.0.1", bridge.port)
            def send(command): writer.write((json.dumps(command) + "\n").encode())
            send({"type": "hello", "token": bridge.token})
            await bridge.wait_connected()
            task = asyncio.create_task(serve_setup(bridge, prefill(settings, config_dir=tmp_path), settings))
            initial = await read_frame(reader)
            assert "tools" in initial and KEY not in json.dumps(initial)
            send({"type": "inspect_tools", "tools_config": "missing.yaml"})
            failed = await read_frame(reader)
            assert failed["type"] == "errors" and "tools_config" in failed["errors"]
            send({"type": "inspect_tools", "tools_config": str(profile)})
            preview = await read_frame(reader)
            assert preview["type"] == "tool_options" and len(preview["tools"]) == 3
            send(payload(tools_config=str(profile), selected_tools=["custom:optional_http"]))
            assert await read_frame(reader) == {"type": "accepted"}
            result, code = await task
            assert code == 0 and result.settings_override.custom_tools[0].enabled
            writer.close()
            await writer.wait_closed()
    asyncio.run(scenario())


def test_auth_passes_tool_selection_to_idle_session(monkeypatch, tmp_path, profile):
    from typer.testing import CliRunner
    import cli.main as main
    settings = Settings()
    result, _ = validate_setup(payload(tools_config=str(profile), selected_tools=["custom:optional_http"]), prefill(settings, config_dir=tmp_path), settings)
    assert result is not None
    def tty_settings(*args):
        monkeypatch.setattr(main.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(main.sys.stdout, "isatty", lambda: True)
        return settings
    monkeypatch.setattr(main, "_settings_with", tty_settings)
    monkeypatch.setattr("cli.launcher.get_config_dir", lambda: tmp_path)
    monkeypatch.setenv("TERM", "xterm")
    calls = []
    async def setup(*args): return result, 0
    async def session(**kwargs): calls.append(kwargs); return 0
    monkeypatch.setattr("cli.launcher.run_rich_setup", setup)
    monkeypatch.setattr("cli.session.run_session", session)
    invocation = CliRunner().invoke(main.app, ["--auth", "--ui", "rich"])
    assert invocation.exit_code == 0, invocation.output
    assert calls[0]["settings"] is result.settings_override
    assert calls[0]["requested_level"] == 0
    assert "optional_http" not in (tmp_path / "launcher.json").read_text()


@pytest.mark.parametrize("configure", [False, True])
def test_rich_optional_configuration_can_be_selected_or_skipped(monkeypatch, tmp_path, profile, configure):
    from cli.launcher import run_rich_setup
    settings = Settings(model={"api_key": KEY})
    monkeypatch.setattr("cli.launcher.sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("cli.launcher.sys.stdout.isatty", lambda: True)
    answers = iter(["", "", "example.org", str(profile) if configure else "", *(["1"] if configure else []), "yes"])
    monkeypatch.setattr("builtins.input", lambda *args: next(answers))
    monkeypatch.setattr("cli.launcher.getpass.getpass", lambda *args: "")
    result, code = asyncio.run(run_rich_setup(prefill(settings, config_dir=tmp_path), settings))
    assert code == 0
    if configure:
        assert result.settings_override.custom_tools[0].enabled
        assert not result.settings_override.custom_tools[1].enabled
    else:
        assert result.settings_override is None


def test_malformed_yaml_is_recoverable_in_preview_and_submit(tmp_path):
    from cli.setup_tools import inspect_tools
    path = tmp_path / "malformed.yaml"
    path.write_text("custom_tools: [broken", encoding="utf-8")
    with pytest.raises(ValueError): inspect_tools(Settings(), str(path))
    settings = Settings()
    result, errors = validate_setup(payload(tools_config=str(path), selected_tools=[]), prefill(settings, config_dir=tmp_path), settings)
    assert result is None and "tools_config" in errors
