"""The published wheel exposes built-in plugins and its CLI away from the checkout."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.smoke
ROOT = Path(__file__).resolve().parents[2]


def test_installed_wheel_plugin_discovery_and_default_cli(tmp_path):
    wheels = tmp_path / 'wheels'
    built = subprocess.run([sys.executable, '-m', 'build', '--wheel', '--no-isolation',
                            '--outdir', str(wheels), str(ROOT)],
                           cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, built.stdout + built.stderr
    wheel = next(wheels.glob('recon_agent-*.whl'))
    target = tmp_path / 'installed'
    installed = subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-deps',
                                '--target', str(target), str(wheel)],
                               cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    env = {**os.environ, 'APPDATA': str(tmp_path / 'config'),
           'XDG_CONFIG_HOME': str(tmp_path / 'config')}
    source = (
        'import sys; sys.path.insert(0, sys.argv.pop(1)); '
        'from agent.cli.main import main; '
        'from agent.plugins import PluginHost; '
        'from agent.tools.registry import build_default; '
        'from agent.gate.scan_gate import ScanGate; '
        'from agent.utils.config import Settings; '
        'registry=build_default(Settings(), ScanGate("example.com", batch_mode=True, is_tty=False), "example.com"); '
        'assert registry.plugin_host.plugin_ids == ("builtin-tools", "builtin-context", "builtin-react"); '
        'main()'
    )
    result = subprocess.run([sys.executable, '-I', '-c', source, str(target), '--list-tools'],
                            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'fingerprint' in result.stdout
