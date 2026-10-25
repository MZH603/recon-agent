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


def test_no_api_key_field_on_global_settings():
    # 凭据属于嵌套模型配置，不是全局运行常量。
    # 外部数据源 API Keys 除外（它们是数据源凭据，非模型凭据）
    fields = Settings.model_fields.keys()
    main_model_keys = [f for f in fields if "key" in f.lower() and f not in (
        "FOFA_API_KEY", "FOFA_API_SECRET",
        "QUAKE_API_KEY", "QUAKE_API_SECRET",
        "ZOOMEYE_API_KEY", "ZOOMEYE_API_SECRET",
        "WEIBU_API_KEY", "WEIBU_API_SECRET",
        "THREATBOOK_API_KEY", "THREATBOOK_API_SECRET",
        "SHODAN_API_KEY", "SHODAN_API_SECRET",
        "CENSYS_API_KEY", "CENSYS_API_SECRET",
        "BINARYEDGE_API_KEY", "BINARYEDGE_API_SECRET",
    )]
    assert not main_model_keys, f"Found main model key fields on global settings: {main_model_keys}"
