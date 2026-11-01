"""集中配置（HARD：代码内禁止硬编码阈值/密钥，魔法数字零容忍，全部常量在此定义）。"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer, field_validator

from platforms.paths import get_config_dir
from security.anonymity.config import AnonymityConfig
from tools.adapters.integration_config import CustomToolConfig, MCPServerConfig
from tools.adapters.extension_config import ExtensionToolsConfig


def optional_api_key(value: str | SecretStr | None) -> SecretStr | None:
    """Normalize blank credentials while keeping configured keys masked."""
    if value is None:
        return None
    if isinstance(value, SecretStr):
        return value if value.get_secret_value().strip() else None
    if not isinstance(value, str):
        raise ValueError("api_key must be a string")
    return SecretStr(value) if value.strip() else None


class ModelConfig(BaseModel):
    """模型接入配置：name 为任意 LiteLLM 支持的模型名，改配置即换模型（HARD：零代码改动）。

    本地模型：model 以 local/、ollama/ 或 llamacpp/ 开头
    示例：
      - local/llama3:8b (LM Studio / llama.cpp server)
      - ollama/qwen2.5:7b (Ollama)
      - llamacpp/mistral-7b-instruct (llama.cpp server)
    """

    model_config = ConfigDict(validate_assignment=True)

    provider: str = "litellm"
    name: str = "gpt-4o-mini"
    api_base: str | None = None
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    api_key_env: str | None = None
    temperature: int = 0  # HARD: 结构化任务确定性最高
    max_retries: int = 2
    timeout: int = 120
    fallback: list[str] = Field(default_factory=lambda: ["claude-3-5-sonnet", "deepseek-chat"])
    custom_endpoints: list[dict] = Field(default_factory=list)

    _normalize_api_key = field_validator("api_key", mode="before")(optional_api_key)

    @field_validator("custom_endpoints", mode="before")
    @classmethod
    def mask_endpoint_keys(cls, endpoints: list[dict]) -> list[dict]:
        return [dict(endpoint, api_key=optional_api_key(endpoint["api_key"]))
                if "api_key" in endpoint else dict(endpoint) for endpoint in endpoints]

    @field_serializer("custom_endpoints")
    def serialize_endpoints(self, endpoints: list[dict]) -> list[dict]:
        return [{key: value for key, value in endpoint.items() if key != "api_key"}
                for endpoint in endpoints]


class Settings(BaseModel):
    """全局安全与运行常量（HARD：不可被 LLM 覆盖，只能由用户在配置文件修改）。"""

    # ---- 隐蔽性与安全（HARD）----
    MAX_CONCURRENCY: int = 1               # 默认并发
    MAX_CONCURRENCY_HARD: int = 2          # 绝对上限，超限自动修正
    REQUEST_DELAY_RANGE: tuple[float, float] = (3.0, 10.0)   # L1/L2 请求间隔（秒，随机）
    L0_DELAY_RANGE: tuple[float, float] = (1.0, 2.5)         # L0 被动请求礼貌间隔
    CONNECT_TIMEOUT: int = 10
    MAX_RETRIES: int = 0                   # HARD: 主动探测失败不重试
    # HARD 绝对红线：政府/军事域名（含中国 .gov.cn/.mil.cn，后缀匹配已验证覆盖）
    PROTECTED_TLDS: tuple[str, ...] = (".gov", ".mil", ".gov.cn", ".mil.cn")
    RFC1918_RANGES: tuple[str, ...] = ("10.", "172.16.", "192.168.", "127.", "169.254.")
    # ---- 匿名层（HARD：默认关闭；关闭时行为与历史版本完全一致）----
    # 结构定义见 security/anonymity/config.py；此处仅挂载，LLM 不可见不可改。
    anonymity: AnonymityConfig = Field(default_factory=AnonymityConfig)
    # ---- 实验环境模式（--lab）----
    # HARD：仅用于操作者自有/自建的内部实验目标（家庭靶场、DVWA、自有设备）。
    # 解锁 RFC1918/内网/环回；绝对红线不受任何模式影响：
    # .gov/.mil 政府军事域名 与 169.254 链路本地/云元数据地址 永久拒绝。
    LAB_MODE: bool = False
    NMAP_ARGS_SAFE: list[str] = ["-sT", "--max-rate", "1", "--max-parallelism", "1"]  # HARD: 仅 TCP Connect
    FORBIDDEN_NMAP_ARGS: list[str] = ["-sS", "-sU", "-A", "-sV", "--version-all"]     # HARD: 禁止项

    # ---- 扫描深度门控（HARD）----
    # 级别体系（v1.1 起三级）：L1 基础侦察（被动采集+隐蔽端口扫描，一次确认）
    # / L2 深度探测（三级门控）/ L3 自适应低扰动激进（沿用 L2 强度）。
    # 原 L0 纯被动档已并入 L1；gate 内部 0 值仅表示"未解锁"（不执行任何采集）。
    SCAN_LEVEL_DEFAULT: int = 1            # 默认 L1 基础侦察
    GATE_CONFIRM_CODES: tuple[str, str, str] = ("CONFIRM 2", "{target}", "I UNDERSTAND AND AUTHORIZE")
    GATE_CONFIRM_CODES_L3: tuple[str, str, str] = ("CONFIRM 3", "{target}", "I UNDERSTAND AND AUTHORIZE")
    GATE_PER_STEP_CONFIRM: bool = True     # L2/L3 逐项确认
    GATE_SESSION_SCOPED: bool = True       # 三级确认仅当次会话有效
    GATE_DISABLE_IN_BATCH: bool = True     # 非交互模式禁止 L2/L3
    GATE_LEVEL2_REQUIRES_TTY: bool = True  # --level 2/3 必须 TTY

    # ---- L3 自适应低扰动（HARD：绝对底线=不影响目标正常活动，熔断即停）----
    L3_DELAY_FLOOR: tuple[float, float] = (2.0, 5.0)    # 目标耐受时的延迟下界
    L3_DELAY_CEIL: tuple[float, float] = (8.0, 20.0)    # 目标不适时的延迟上界
    L3_COOLDOWN_RANGE: tuple[float, float] = (60.0, 300.0)   # 冷却时长（Retry-After 优先）
    L3_BLOCK_SUSPEND_THRESHOLD: int = 3   # 连续阻断次数 → 熔断该主机（sampling_suspended）
    L3_RTT_DOUBLE_FACTOR: float = 2.0     # RTT 超基线倍数 → wary
    L3_SUCCESS_RELAX_STREAK: int = 5      # 连续成功次数 → 向 floor 收敛一档
    L3_MAX_RETRIES: int = 1               # HARD: 仅连接层失败重试 1 次（退避≥10s）；4xx/5xx 是答案不重试
    L3_RETRY_BACKOFF: float = 10.0        # 连接层重试退避下限（秒）
    L3_CONCURRENCY: int = 2               # L3 全局并发默认（per-host 仍串行）
    L3_CONCURRENCY_HARD: int = 4          # L3 全局并发绝对上限
    L3_MAX_REQUESTS_PER_HOST: int = 30    # HARD: L3 单主机请求预算
    DNS_WORDLIST_L3_CAP: int = 5000       # HARD: L3 DNS 字典上限（打公共解析器，不碰目标 NS）
    DNS_BRUTE_L3_CONCURRENCY: int = 10    # L3 DNS 爆破并发（仅公共解析器查询）
    DIR_PATHS_L3_CAP: int = 300           # HARD: L3 目录枚举路径上限
    VHOST_WORDLIST_CAP: int = 200         # HARD: vhost 候选上限
    CLOUD_BUCKET_CAP: int = 40            # HARD: 云存储 bucket 候选上限
    L3_SYNSCAN_MAX_RATE: int = 10         # HARD: tier1 SYN 扫描速率上限（nmap --max-rate）
    L3_UDP_PORTS: str = "53,123,161,500,514,1900"   # tier1 UDP 探测端口（低强度白名单）
    NMAP_ARGS_L3_TIER1: list[str] = ["-sS", "-sU", "-sV", "--version-intensity"]  # 仅 level==3 且逐项确认后放行

    # ---- Token / 上下文 ----
    CONTEXT_BUDGET: int = Field(default=100_000, gt=0)
    COMPRESS_THRESHOLD: int = 1_500        # 超过即落盘（tokens 粗估）
    COMPACT_TRIGGER_RATIO: float = Field(default=0.70, gt=0, lt=1, allow_inf_nan=False)
    CACHE_TTL_SECONDS: int = 86_400

    # ---- User-configured tool integrations (no external startup by default) ----
    custom_tools: list[CustomToolConfig] = Field(default_factory=list)
    mcp_servers: list[MCPServerConfig] = Field(default_factory=list)
    extension_tools: ExtensionToolsConfig = Field(default_factory=ExtensionToolsConfig)
    TOOL_EVIDENCE_DIR: str = ""
    TOOL_TIMEOUT_SECONDS: float = Field(default=120, gt=0,allow_inf_nan=False)
    SUBDOMAIN_ENUM_TIMEOUT_SECONDS: float = Field(default=1800, ge=120, le=3600)
    TOOL_CLEANUP_SECONDS: float = Field(default=5, gt=0,allow_inf_nan=False)
    TOOL_TIMEOUT_OVERRIDES: dict[str, float] = Field(default_factory=dict)
    TOOL_RESULT_MAX_BYTES: int = Field(default=16000, ge=1024)
    SESSION_PROMPT_FILE: str = ""
    TUI_THEME: str = "dark"

    @field_validator('TOOL_TIMEOUT_OVERRIDES')
    @classmethod
    def positive_tool_timeouts(cls, values):
        import math
        if any(not math.isfinite(v) or v <= 0 for v in values.values()):
            raise ValueError('tool timeouts must be finite and positive')
        return values
    API_RECON_MAX_REQUESTS: int = Field(default=8, ge=1, le=8)
    API_RECON_MAX_ASSET_BYTES: int = Field(default=100_000, ge=1024, le=100_000)
    API_RECON_TIMEOUT_SECONDS: float = Field(default=30, ge=1, le=120)

    # ---- 模型 ----
    model: ModelConfig = Field(default_factory=ModelConfig)

    # ---- 预算 ----
    MAX_COST_PER_TASK: float = 2.0
    MAX_TOKENS_PER_TASK: int = 0           # 旧配置兼容字段，不再作为限制

    # ---- 提效减耗 ----
    DEDUP_ENABLED: bool = True
    DEDUP_TTL_SECONDS: int = 86_400
    INCREMENTAL_UPDATES: bool = True
    TRIM_AGGRESSIVENESS: str = "balanced"
    TEMPLATE_COMPRESSION: bool = True
    TARGET_TOKEN_REDUCTION: float = 0.20

    # ---- 沙箱 ----
    SANDBOX_ENABLED: bool = True
    SANDBOX_USE_DOCKER: bool = False       # 可选，需 Linux + Docker
    SANDBOX_TIMEOUT: int = 30
    SANDBOX_MEMORY_LIMIT: str = "128m"
    SANDBOX_NETWORK: str = "none"

    # ---- 抗幻觉 ----
    EVIDENCE_REQUIRED: bool = True         # 强制证据绑定
    SOURCE_HASH_ENABLED: bool = True
    CONSISTENCY_CHECK_BLOCKS_REPORT: bool = False  # CI 下可开启

    # ---- 外部数据源 API Keys ----
    FOFA_API_KEY: str = ""
    FOFA_API_SECRET: str = ""
    QUAKE_API_KEY: str = ""
    QUAKE_API_SECRET: str = ""
    ZOOMEYE_API_KEY: str = ""
    ZOOMEYE_API_SECRET: str = ""
    WEIBU_API_KEY: str = ""
    WEIBU_API_SECRET: str = ""
    THREATBOOK_API_KEY: str = ""
    THREATBOOK_API_SECRET: str = ""
    SHODAN_API_KEY: str = ""
    SHODAN_API_SECRET: str = ""
    CENSYS_API_KEY: str = ""
    CENSYS_API_SECRET: str = ""
    BINARYEDGE_API_KEY: str = ""
    BINARYEDGE_API_SECRET: str = ""
    HUNTER_API_KEY: str = ""            # 鹰图 hunter.qianxin.com
    HUNTER_API_SECRET: str = ""
    NETLAS_API_KEY: str = ""            # app.netlas.net
    NETLAS_API_SECRET: str = ""
    VIRUSTOTAL_API_KEY: str = ""        # 免费额度 4 req/min（延迟已相应放宽）
    VIRUSTOTAL_API_SECRET: str = ""
    SECURITYTRAILS_API_KEY: str = ""    # 子域 + 历史 A 记录（DNS 历史）
    SECURITYTRAILS_API_SECRET: str = ""
    # 新数据源限速（datasource 适配器按 {NAME}_DELAY_RANGE 反射读取；未定义走默认 (3,10)）
    VIRUSTOTAL_DELAY_RANGE: tuple[float, float] = (20.0, 40.0)   # 4 req/min
    HUNTER_DELAY_RANGE: tuple[float, float] = (2.0, 5.0)

    # ---- 情报扩容源（Phase A：代码泄漏/组织情报/dorking）----
    GITHUB_API_KEY: str = ""            # GitHub PAT（code search 强制认证）
    GITEE_API_KEY: str = ""             # Gitee 私人令牌（可选）
    ICP_API_URL: str = ""               # ICP 备案查询 HTTP 模板（含 {domain} 占位符）；空=跳过
    ICP_API_KEY: str = ""               # ICP 查询源鉴权（随源而定）
    ORG_API_BASE: str = ""              # 企业信息 API 通用插槽（企查查/天眼查等自配）
    ORG_API_KEY: str = ""
    DORK_MAX_REQUESTS: int = 20         # HARD: dork_search 出站请求总预算
    DORK_BACKENDS: list[str] = ["duckduckgo", "baidu"]  # 依次降级；exa/perplexity 需 env key
    CODELEAK_MAX_DORKS: int = 10        # HARD: code_leak_search dork 查询预算
    CODELEAK_MAX_RESULTS: int = 30      # 单 dork 收录结果上限

    @classmethod
    def load(cls, config_path: Path | None = None) -> "Settings":
        """从项目根 config.yaml / 用户配置目录加载；文件缺失用默认值。"""
        candidates = [Path("config.yaml")]
        if config_path:
            candidates.insert(0, Path(config_path))
        else:
            candidates.append(get_config_dir() / "config.yaml")
        for path in candidates:
            if path.exists():
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                model_data = data.pop("model", {})
                settings = cls(**data)
                if model_data:
                    settings.model = ModelConfig(**model_data)
                return settings
        return cls()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """进程级单例（HARD：任何模块不得绕过 Settings 自定阈值）。"""
    return Settings.load()
