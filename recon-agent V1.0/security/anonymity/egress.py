"""统一出站出口（HARD：kill-switch fail closed；环境变量代理防劫持；匿名关闭时零行为变更）。

路由语义：
- 匿名关闭  → 直连（与历史行为一致，含系统环境代理——不改变现状）；
- 匿名开启  → 一律经配置出口（HTTP(S)/SOCKS5/Tor），显式屏蔽环境代理变量，
              无健康出口且 kill_switch=True 时拒绝出站（AnonymityRequiredError），
              kill_switch=False 时允许降级直连但全量审计（用户显式接受风险）。
"""
from __future__ import annotations

import http.client
import ssl
import threading
import urllib.error
import urllib.request

from security.anonymity import tunnel
from security.anonymity.config import AnonymityConfig, ProxyEndpoint
from security.http_scope import _SameHostRedirectHandler
from utils.logger import audit

_last_endpoint = threading.local()   # 当前线程最近一次选出的出口（失败反馈用）

_KILL_SWITCH_SKIP_DOMAINS: tuple[str, ...] = ()  # 预留：极特殊本地场景白名单（当前为空=无）


class AnonymityRequiredError(Exception):
    """kill-switch 触发：匿名已启用但无可用出口，拒绝出站（绝不直连）。"""


def get_anonymity_config() -> AnonymityConfig:
    """从全局 Settings 取匿名配置（延迟导入防循环）。"""
    from utils.config import get_settings
    return get_settings().anonymity


def resolve_endpoints(config: AnonymityConfig) -> list[ProxyEndpoint]:
    """按 mode 解析实际出口列表（tor 模式隐式注入本机 SOCKS5 出口）。"""
    if config.mode == "tor":
        url = f"socks5://{config.tor_socks_host}:{config.tor_socks_port}"
        return [ProxyEndpoint(url=url, tag="tor", region="tor")]
    return list(config.proxies)


def active_endpoint(target_key: str = "", config: AnonymityConfig | None = None) -> ProxyEndpoint | None:
    """取当前可用出口；未启用/不可用返回 None。"""
    cfg = config or get_anonymity_config()
    if not cfg.enabled:
        return None
    if cfg.mode == "pool":
        from security.anonymity.pool import ProxyPool
        return _pool_for(cfg).acquire(target_key)
    endpoints = resolve_endpoints(cfg)
    if not endpoints:
        return None
    return endpoints[0]


_POOL_CACHE: dict[int, "object"] = {}


def _pool_for(config: AnonymityConfig):
    """进程级单例池（配置对象身份为键，测试中可替换配置）。"""
    from security.anonymity.pool import ProxyPool
    key = id(config)
    pool = _POOL_CACHE.get(key)
    if pool is None:
        pool = ProxyPool(
            resolve_endpoints(config),
            rotation=config.rotation,
            fail_cooldown_seconds=config.fail_cooldown_seconds,
            health_interval_seconds=config.health_interval_seconds,
            probe_url=config.probe_url,
        )
        _POOL_CACHE[key] = pool
    return pool


def require_anonymity_or_raise(target_key: str = "",
                               config: AnonymityConfig | None = None) -> ProxyEndpoint | None:
    """kill-switch（HARD）：返回可用出口；None=审计后允许直连（仅 kill_switch=False）。

    - 匿名未启用            → None（直连，历史行为）；
    - 有可用出口            → ProxyEndpoint（调用方必须经该出口）；
    - 无出口 kill_switch=True  → raise AnonymityRequiredError（fail closed，绝不直连）；
    - 无出口 kill_switch=False → 审计 anon_bypass_direct 后返回 None（用户显式接受暴露风险）。
    """
    cfg = config or get_anonymity_config()
    if not cfg.enabled:
        return None
    endpoint = active_endpoint(target_key, cfg)
    if endpoint is not None:
        _last_endpoint.value = endpoint   # 单一选择点：供成功/失败反馈定位当前出口
        return endpoint
    if cfg.kill_switch:
        audit("anon_kill_switch_blocked", {"target_key": target_key[:64]})
        raise AnonymityRequiredError(
            "匿名层已启用且 kill_switch=True，但无可用代理出口；已拒绝出站（防真实 IP 泄露）。"
            "请检查 config.yaml anonymity.proxies 或临时关闭 anonymity.enabled。")
    audit("anon_bypass_direct", {"target_key": target_key[:64],
                                 "risk": "user-accepted-direct-egress"})
    return None


# ---------------- urllib opener 组装 ----------------

def _proxy_scheme(proxy_url: str) -> str:
    parsed = urllib.request.urlsplit(proxy_url)
    scheme = (parsed.scheme or "").lower()
    return "socks5" if scheme == "socks5h" else scheme


def _make_tunnel_connection_classes(proxy_url: str, insecure: bool,
                                    ssl_context: ssl.SSLContext | None):
    """SOCKS5 出口的 http.client 连接类：connect() 先建隧道再（可选）TLS。"""
    base_timeout = 30.0

    class _TunnelHTTPConnection(http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._tunnel_timeout = self.timeout or base_timeout

        def connect(self):
            sock = tunnel.connect_sync(proxy_url, self.host, self.port, self._tunnel_timeout)
            self.sock = sock

    class _TunnelHTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._tunnel_timeout = self.timeout or base_timeout

        def connect(self):
            sock = tunnel.connect_sync(proxy_url, self.host, self.port, self._tunnel_timeout)
            context = ssl_context or self.ssl_context or ssl.create_default_context()
            if insecure:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(sock, server_hostname=self.host)

    return _TunnelHTTPConnection, _TunnelHTTPSConnection


def _tunnel_handlers(proxy_url: str, insecure: bool, ssl_context: ssl.SSLContext | None) -> list:
    http_conn_cls, https_conn_cls = _make_tunnel_connection_classes(proxy_url, insecure, ssl_context)

    class _TunnelHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(http_conn_cls, req)

    class _TunnelHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(https_conn_cls, req)

    return [_TunnelHTTPHandler(), _TunnelHTTPSHandler()]


def _insecure_https_handler():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.HTTPSHandler(context=context)


def build_opener(allowed_origin=None, *, insecure: bool = False,
                 proxy_url: str | None = None,
                 config: AnonymityConfig | None = None) -> urllib.request.OpenerDirector:
    """构建带匿名路由的 urllib opener。

    - proxy_url 显式给出时按其路由（pool 健康探测等内部用途）；
    - 否则按匿名配置解析：未启用 → 不注入任何 handler（与直连历史行为一致）；
      启用 → 走出口隧道并显式 ProxyHandler({}) 屏蔽环境变量代理（防劫持/防意外直连）。
    - allowed_origin 提供时叠加同源重定向约束（复用 http_scope）。
    """
    cfg = config or get_anonymity_config()
    handlers: list = []
    if proxy_url:
        scheme = _proxy_scheme(proxy_url)
        if scheme in ("socks5", "https"):
            # HARD：SOCKS5 与 HTTPS 代理必须走自建隧道（urllib 原生 ProxyHandler
            # 不支持 TLS-to-proxy，https:// 代理会退化为明文 CONNECT）。
            handlers.extend(_tunnel_handlers(proxy_url, insecure, None))
        else:
            if insecure:
                handlers.append(_insecure_https_handler())
            handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    elif cfg.enabled:
        try:
            endpoint = require_anonymity_or_raise("", cfg)
        except AnonymityRequiredError:
            raise
        if endpoint is not None:
            _last_endpoint.value = endpoint
            scheme = _proxy_scheme(endpoint.url)
            if scheme in ("socks5", "https"):
                handlers.extend(_tunnel_handlers(endpoint.url, insecure, None))
            else:
                handlers.append(urllib.request.ProxyHandler({"http": endpoint.url,
                                                             "https": endpoint.url}))
            # HARD：匿名路径下显式清空环境代理，防止 HTTP_PROXY 变量造成意外直连/劫持
            handlers.append(urllib.request.ProxyHandler({}))
        # endpoint is None：kill_switch=False 审计后直连，不注入任何 handler
    if allowed_origin is not None:
        handlers.append(_SameHostRedirectHandler(allowed_origin))
    if insecure and not any(isinstance(h, urllib.request.HTTPSHandler) for h in handlers):
        handlers.append(_insecure_https_handler())
    return urllib.request.build_opener(*handlers)


def opener_for_proxy(proxy_url: str, insecure: bool = False):
    """指定单一代理 URL 的 opener（池健康探测 / doctor 用）。"""
    return build_opener(proxy_url=proxy_url, insecure=insecure,
                        config=AnonymityConfig(enabled=False))


def urlopen_same_origin(request: urllib.request.Request, *, timeout: float,
                        insecure: bool = False,
                        config: AnonymityConfig | None = None):
    """同源受限打开（匿名层感知版 urlopen_same_host：重定向出源即拒绝）。"""
    origin = _origin_tuple(request.full_url)
    opener = build_opener(allowed_origin=origin, insecure=insecure, config=config)
    return opener.open(request, timeout=timeout)


def _origin_tuple(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) 三元组（与 http_scope 同语义，供 opener 约束用）。"""
    from security.http_scope import _origin_tuple as _ot
    return _ot(url)


def check_exit_ip(proxy_url: str, timeout: float = 10.0) -> str | None:
    """经指定出口请求 IP 回显服务，返回出口 IP（doctor 显式调用，默认不调用）。

    注意：出口 IP 会提供给回显服务（非目标方）；用于人工核验代理是否生效。
    """
    try:
        opener = opener_for_proxy(proxy_url)
        req = urllib.request.Request("https://api.ipify.org",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=timeout) as resp:
            return resp.read(64).decode("ascii", "replace").strip() or None
    except (OSError, ValueError, urllib.error.HTTPError):
        return None


def is_anonymity_enabled() -> bool:
    """快捷判断（不触发 kill-switch，仅读配置）。"""
    cfg = get_anonymity_config()
    if not cfg.enabled:
        return False
    return bool(resolve_endpoints(cfg))


def report_egress_failure() -> None:
    """请求失败反馈：当前线程出口进入冷却（pool 模式），single/tor 模式仅审计。

    调用方：统一出口的连接失败分支（HARD：死出口必须被剔除，防止反复撞墙）。
    """
    endpoint = getattr(_last_endpoint, "value", None)
    if endpoint is None:
        return
    cfg = get_anonymity_config()
    if cfg.enabled and cfg.mode == "pool":
        _pool_for(cfg).report_failure(endpoint)
    else:
        audit("proxy_failed", {"url": endpoint.url.split("://")[0] + "://<masked>",
                               "mode": cfg.mode})


def report_egress_success(latency_ms: float = -1.0) -> None:
    """请求成功反馈：重置出口健康状态并记录延迟（pool 模式）。"""
    endpoint = getattr(_last_endpoint, "value", None)
    if endpoint is None:
        return
    cfg = get_anonymity_config()
    if cfg.enabled and cfg.mode == "pool":
        _pool_for(cfg).report_success(endpoint, latency_ms)
