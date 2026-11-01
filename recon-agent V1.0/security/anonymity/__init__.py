"""匿名安全层（HARD：默认关闭；关闭时所有路径行为与历史版本一致）。

模块导出：
- egress      统一出站出口 / kill-switch（require_anonymity_or_raise / build_opener）
- pool        代理 IP 池（ProxyPool：轮换/健康/冷却）
- tunnel      HTTP CONNECT / SOCKS5 隧道原语 + Tor NEWNYM
- fingerprint 反指纹头部档案（会话内稳定、跨会话轮换）
- dns_privacy DoH 反溯源解析
- trace_cleanup 痕迹清理（session/artifacts/system 白名单制）
"""
from security.anonymity.config import AnonymityConfig, ProxyEndpoint
from security.anonymity.egress import (
    AnonymityRequiredError,
    active_endpoint,
    build_opener,
    check_exit_ip,
    is_anonymity_enabled,
    require_anonymity_or_raise,
    resolve_endpoints,
)

__all__ = [
    "AnonymityConfig",
    "ProxyEndpoint",
    "AnonymityRequiredError",
    "active_endpoint",
    "build_opener",
    "check_exit_ip",
    "is_anonymity_enabled",
    "require_anonymity_or_raise",
    "resolve_endpoints",
]
