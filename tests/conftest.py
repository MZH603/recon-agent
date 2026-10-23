"""真实进程测试：仅通过环境、配置文件和标准输入控制应用。"""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def app_env(tmp_path):
    # 白名单继承启动进程所需变量，避免读取操作者的模型凭据、代理或配置。
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
               "USERPROFILE", "HOME"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(
        APPDATA=str(tmp_path / "config"),
        XDG_CONFIG_HOME=str(tmp_path / "config"),
        PYTHONPATH=str(ROOT),
        PYTHONIOENCODING="utf-8",
        PYTHONUTF8="1",
        NO_COLOR="1",
        TERM="dumb",
        COLUMNS="200",
        LITELLM_LOCAL_MODEL_COST_MAP="True",
    )
    work = tmp_path / "work"
    work.mkdir()
    # JSON 是合法 YAML；避免加载仓库或用户本机的 config.yaml。
    config = {
        "LAB_MODE": True,
        "L0_DELAY_RANGE": [0, 0],
        "REQUEST_DELAY_RANGE": [0, 0],
        "model": {
            "name": "openai/gpt-4o-mini",
            "api_base": "http://127.0.0.1:1/v1",
            "api_key": "local-test-only",
            "fallback": [],
            "max_retries": 0,
            "timeout": 5,
        },
    }
    (work / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
    return env


@pytest.fixture
def run_app(app_env, tmp_path):
    def run(*args, module="cli.main", input_text=""):
        return subprocess.run(
            [sys.executable, "-m", module, *args],
            cwd=tmp_path / "work", env=app_env, input=input_text,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60,
        )
    return run
