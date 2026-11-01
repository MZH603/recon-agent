"""反指纹头部档案测试：会话内一致 / 跨会话轮换 / 语义完整 / 统一入口。"""
from security.anonymity.config import AnonymityConfig as AnonCfg, ProxyEndpoint
from security.anonymity.fingerprint import (
    default_session_id,
    request_headers,
    session_profile,
)


def test_session_profile_stable_within_session():
    """HARD 语义：同一 session_id 头部档案稳定（防同会话多指纹异常）。"""
    first = session_profile("session-abc")
    for _ in range(5):
        assert session_profile("session-abc") == first


def test_profiles_vary_across_sessions():
    """不同 session_id 应分布到不同档案（跨会话轮换）。"""
    chosen = {tuple(sorted(session_profile(f"s{i}").items())) for i in range(9)}
    assert len(chosen) >= 2


def test_profile_semantic_consistency():
    """档案必须语义一致：sec-ch-ua 平台与 UA 平台对应（Chrome/Windows ↔ Windows）。"""
    for i in range(6):
        profile = session_profile(f"seed-{i}")
        ua = profile["User-Agent"]
        if "Chrome" in ua:
            assert profile["sec-ch-ua-platform"] == '"Windows"'
            assert '"Chromium"' in profile["sec-ch-ua"]
        if "Firefox" in ua:
            assert "sec-ch-ua" not in profile      # Firefox 不发 Client Hints
        assert profile["Accept-Language"].startswith("zh")


def test_resource_purpose_strips_nav_headers():
    """purpose=resource 剥离导航语义头部（Sec-Fetch-User / Upgrade-Insecure-Requests）。"""
    full = session_profile("s", purpose="document")
    res = session_profile("s", purpose="resource")
    assert "Upgrade-Insecure-Requests" in full
    assert "Upgrade-Insecure-Requests" not in res
    assert res["User-Agent"] == full["User-Agent"]     # UA 保持一致


def test_empty_session_falls_back_to_random():
    """无会话上下文：退化为随机档案（仍仅白名单 UA）。"""
    from security.stealth import BROWSER_UAS
    for _ in range(4):
        assert session_profile("")["User-Agent"] in BROWSER_UAS


def test_request_headers_disabled_keeps_legacy_shape():
    """匿名关闭：仅随机浏览器 UA（与历史 stealth 行为完全一致）。"""
    from security.stealth import BROWSER_UAS
    headers = request_headers()
    assert set(headers) == {"User-Agent"}
    assert headers["User-Agent"] in BROWSER_UAS


def test_request_headers_enabled_uses_full_profile(monkeypatch):
    """匿名启用：完整档案 + 进程级稳定身份。"""
    from security.anonymity import egress
    monkeypatch.setattr(egress, "get_anonymity_config",
                        lambda: AnonCfg(enabled=True, proxies=[ProxyEndpoint(url="socks5://10.0.0.1:1080")]))
    h1 = request_headers()
    h2 = request_headers()
    assert h1 == h2                                   # 进程内稳定
    assert "sec-ch-ua" in h1 or "Upgrade-Insecure-Requests" in h1


def test_default_session_id_is_stable_process_identity():
    """进程级身份：同进程稳定、非空。"""
    assert default_session_id() == default_session_id()
    assert default_session_id()
