"""配置契约测试。"""
from utils.config import Settings, get_settings


def test_stealth_defaults():
    s = get_settings()
    assert s.MAX_CONCURRENCY == 1
    assert s.MAX_CONCURRENCY_HARD == 2
    assert s.MAX_RETRIES == 0  # HARD: 失败不重试
    assert s.SCAN_LEVEL_DEFAULT == 0
    assert s.NMAP_ARGS_SAFE[0] == "-sT"  # 仅 TCP Connect
    assert "-sS" in s.FORBIDDEN_NMAP_ARGS


def test_yaml_override(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("model:\n  name: deepseek-chat\n", encoding="utf-8")
    s = Settings.load(cfg)
    assert s.model.name == "deepseek-chat"
    assert s.MAX_CONCURRENCY == 1  # 安全常量不受模型配置影响


def test_api_key_only_from_env():
    # HARD: key 只走环境变量；配置文件里不存在 key 字段
    fields = Settings.model_fields.keys()
    assert not any("key" in f.lower() for f in fields)
