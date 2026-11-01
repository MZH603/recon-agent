"""统一出站出口测试：关闭透传 / kill-switch fail-closed / 环境代理屏蔽 / bypass 审计。"""
import urllib.request

import pytest

from security.anonymity.config import AnonymityConfig, ProxyEndpoint
from security.anonymity.egress import (
    AnonymityRequiredError,
    active_endpoint,
    build_opener,
    is_anonymity_enabled,
    require_anonymity_or_raise,
    resolve_endpoints,
)


def test_disabled_is_passthrough():
    """enabled=False：active_endpoint=None、require 返回 None、opener 等价默认处理器集。"""
    cfg = AnonymityConfig(enabled=False)
    assert active_endpoint("t", cfg) is None
    assert require_anonymity_or_raise("t", cfg) is None
    assert not is_anonymity_enabled()
    opener = build_opener(config=cfg)
    names = {type(h).__name__ for h in opener.handlers}
    assert "HTTPHandler" in names and "HTTPSHandler" in names
    # 未注入任何隧道/空代理处理器（与历史直连行为一致）
    assert not any("Tunnel" in n for n in names)


def test_enabled_without_proxies_kill_switch_blocks():
    """HARD kill-switch：启用但无出口 → raise AnonymityRequiredError，绝不直连。"""
    cfg = AnonymityConfig(enabled=True, proxies=[])
    with pytest.raises(AnonymityRequiredError):
        require_anonymity_or_raise("t", cfg)
    with pytest.raises(AnonymityRequiredError):
        build_opener(config=cfg)


def test_kill_switch_off_allows_bypass_with_audit():
    """kill_switch=False：无出口时审计 anon_bypass_direct 后放行直连（用户显式接受风险）。"""
    import json

    from utils.logger import audit_path
    cfg = AnonymityConfig(enabled=True, proxies=[], kill_switch=False)
    assert require_anonymity_or_raise("t", cfg) is None
    entries = [json.loads(line) for line in audit_path().read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "anon_bypass_direct" for e in entries)


def test_tor_mode_injects_local_socks_endpoint():
    """mode=tor：隐式注入 socks5://127.0.0.1:9050 出口，无需手工 proxies。"""
    cfg = AnonymityConfig(enabled=True, mode="tor")
    endpoints = resolve_endpoints(cfg)
    assert len(endpoints) == 1
    assert endpoints[0].scheme == "socks5"
    assert endpoints[0].url == "socks5://127.0.0.1:9050"


def test_single_mode_uses_first_proxy():
    """mode=single：取配置列表第一个出口。"""
    cfg = AnonymityConfig(enabled=True, proxies=[
        ProxyEndpoint(url="socks5://10.0.0.1:1080"),
        ProxyEndpoint(url="http://10.0.0.2:8080"),
    ])
    assert active_endpoint("t", cfg).url == "socks5://10.0.0.1:1080"


def test_enabled_build_opener_blocks_env_proxy():
    """HARD 反劫持：匿名路径下无任何环境代理参与（空 ProxyHandler 不注册 → 无代理路由）。"""
    cfg = AnonymityConfig(enabled=True, proxies=[ProxyEndpoint(url="socks5://10.0.0.1:1080")])
    opener = build_opener(config=cfg)
    proxy_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy_handlers == []                     # HTTP_PROXY/HTTPS_PROXY 环境变量被中和
    assert any("Tunnel" in type(h).__name__ for h in opener.handlers)  # SOCKS5 隧道处理器在场


def test_http_proxy_uses_native_proxy_handler():
    """HTTP(S) 代理：走 urllib 原生 ProxyHandler（CONNECT/认证由 urllib 处理）。"""
    cfg = AnonymityConfig(enabled=True, proxies=[ProxyEndpoint(url="http://user:pass@10.0.0.3:8080")])
    opener = build_opener(config=cfg)
    proxy_handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert "10.0.0.3:8080" in proxy_handlers[0].proxies["http"]
    assert not any("Tunnel" in type(h).__name__ for h in opener.handlers)


def test_https_proxy_routes_through_tunnel():
    """HARD 回归：https:// 代理必须走自建隧道（urllib 原生 ProxyHandler 不支持
    TLS-to-proxy，明文 CONNECT 会对真 HTTPS 代理失效）。"""
    cfg = AnonymityConfig(enabled=True, proxies=[ProxyEndpoint(url="https://u:p@10.0.0.4:8443")])
    opener = build_opener(config=cfg)
    assert any("Tunnel" in type(h).__name__ for h in opener.handlers)
    assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
                   for h in opener.handlers)


def test_explicit_proxy_url_https_also_tunneled():
    """显式 proxy_url 参数（池探测路径）同样对 https 代理走隧道。"""
    opener = build_opener(proxy_url="https://10.0.0.4:8443",
                          config=AnonymityConfig(enabled=False))
    assert any("Tunnel" in type(h).__name__ for h in opener.handlers)


def test_probe_url_must_be_https():
    """HARD：健康探测 URL 仅允许 https（探测内容不得明文）。"""
    with pytest.raises(ValueError):
        AnonymityConfig(probe_url="http://www.gstatic.com/generate_204")


def test_proxy_endpoint_scheme_validation():
    """代理 URL scheme 白名单：http/https/socks5(/socks5h)，其余拒绝。"""
    with pytest.raises(ValueError):
        ProxyEndpoint(url="ftp://10.0.0.1:21")
    with pytest.raises(ValueError):
        ProxyEndpoint(url="10.0.0.1:1080")  # 缺 scheme
    assert ProxyEndpoint(url="socks5h://10.0.0.1:1080").scheme == "socks5"
