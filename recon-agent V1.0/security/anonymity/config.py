"""匿名层配置模型（HARD：只定义结构，不 import utils.config —— 防循环依赖）。

默认 enabled=False：匿名层关闭时所有路径行为与历史版本完全一致。
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ProxyScheme = Literal["http", "https", "socks5"]
RotationStrategy = Literal["round_robin", "random", "sticky"]
AnonMode = Literal["single", "pool", "tor"]
CleanupScope = Literal["session", "artifacts", "system", "all"]

# HARD：健康检查探测目标必须是无状态轻量端点，不得探测目标本身
DEFAULT_PROBE_URL = "https://www.gstatic.com/generate_204"
PROBE_TIMEOUT_SECONDS: float = 8.0
PROBE_MAX_CONCURRENCY: int = 2          # HARD：与全局并发红线一致

DEFAULT_DOH_RESOLVERS: tuple[str, ...] = (
    "https://223.5.5.5/resolve",        # 阿里 DoH（JSON API）
    "https://1.1.1.1/dns-query",        # Cloudflare DoH（JSON API）
    "https://doh.google/resolve",       # Google DoH
)
DOH_TIMEOUT_SECONDS: float = 8.0
DOH_CACHE_TTL_SECONDS: int = 600        # 解析结果缓存（防止重复 DoH 查询泄露频率特征）

TOR_DEFAULT_CONTROL_PORT: int = 9051
TOR_CONTROL_TIMEOUT_SECONDS: float = 10.0

CLEANUP_SHRED_ROUNDS: int = 1           # 单遍覆写（HARD：SSD/COW 文件系统下不承诺取证级）


class ProxyEndpoint(BaseModel):
    """单个代理出口：URL 形如 socks5://[user:pass@]host:port 或 http(s)://...。"""

    model_config = ConfigDict(validate_assignment=True)

    url: str = Field(min_length=1, max_length=512)
    tag: str = Field(default="", max_length=64)      # 供应商/来源标记
    region: str = Field(default="", max_length=32)   # 出口地区（信息性）
    weight: int = Field(default=1, ge=1, le=100)

    @field_validator("url")
    @classmethod
    def check_scheme(cls, value: str) -> str:
        value = value.strip()
        if "://" not in value:
            raise ValueError("proxy url 必须带 scheme: http:// / https:// / socks5://")
        scheme = value.split("://", 1)[0].lower()
        if scheme not in ("http", "https", "socks5", "socks5h"):
            raise ValueError(f"不支持的代理 scheme: {scheme}")
        return value

    @property
    def scheme(self) -> str:
        scheme = self.url.split("://", 1)[0].lower()
        # socks5h 与 socks5 语义相同：域名一律由代理端远端解析（反 DNS 溯源）
        return "socks5" if scheme == "socks5h" else scheme


class AnonymityConfig(BaseModel):
    """匿名层总配置（HARD：默认关闭；仅用户在 config.yaml 修改，LLM 不可见不可改）。"""

    model_config = ConfigDict(validate_assignment=True)

    enabled: bool = False

    # single=固定单出口；pool=多出口轮换；tor=本机 Tor SOCKS5（可配合控制端口 NEWNYM）
    mode: AnonMode = "single"
    proxies: list[ProxyEndpoint] = Field(default_factory=list)

    # sticky：同一目标固定同一出口（防 IP 抖动关联指纹），不同目标间轮换
    rotation: RotationStrategy = "sticky"

    # Tor：mode=tor 时使用，隐式等价 proxies=[socks5://127.0.0.1:9050]
    tor_socks_host: str = "127.0.0.1"
    tor_socks_port: int = Field(default=9050, ge=1, le=65535)
    tor_control_port: int = Field(default=9051, ge=1, le=65535)
    tor_control_password: str = ""                     # 留空且启 Cookie 认证时读 auth cookie
    tor_newnym_per_target: bool = False                # 每个新目标换一次 Tor 电路

    # kill-switch（HARD）：启用匿名但无健康出口 → 拒绝出站（fail closed），绝不直连
    kill_switch: bool = True

    # 健康检查
    health_interval_seconds: int = Field(default=300, ge=30, le=86400)
    fail_cooldown_seconds: int = Field(default=600, ge=10, le=86400)
    probe_url: str = DEFAULT_PROBE_URL

    # DNS 反溯源
    doh_enabled: bool = False                          # 默认关闭：关闭时系统解析，行为不变
    doh_strict: bool = False                           # True=DoH 失败拒绝出站而非降级系统解析
    doh_resolvers: list[str] = Field(default_factory=lambda: list(DEFAULT_DOH_RESOLVERS))

    # 痕迹清理（HARD：审计日志与 reports/ 永不清理）
    cleanup_on_session_end: bool = False               # 会话结束自动清 session 级缓存
    cleanup_keep_evidence: bool = True                 # True=artifacts 范围需显式 CLI 触发

    @field_validator("probe_url")
    @classmethod
    def check_probe_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("probe_url 仅允许 https://（探测内容不得经过 HTTP 明文）")
        return value
