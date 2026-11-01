"""反指纹头部档案（HARD：仅常见浏览器语义一致的头部组合，禁止扫描器标识）。

- 会话内稳定（session_profile 按 session_id 派生）：同一会话 UA/头部一致，防「同会话多指纹」异常；
- 跨会话轮换（不同 session_id 哈希到不同档案）；
- 与 sticky 出口绑定：egress 层用 target_key 选出口，头部用同一 target_key 派生 → IP/UA 语义稳定对应。
"""
from __future__ import annotations

import hashlib
import uuid

from security.stealth import BROWSER_UAS

_PROCESS_SESSION_ID: str = uuid.uuid4().hex   # 进程级稳定会话身份（匿名启用时头部一致性锚点）


def default_session_id() -> str:
    """进程级会话身份：同进程内头部档案稳定，进程间（每次运行）轮换。"""
    return _PROCESS_SESSION_ID

# 每个档案 = 一致语义的完整浏览器头部组（sec-ch-ua 与 UA 版本对应、语言与 UA 平台一致）
_PROFILE_SEEDS: tuple[dict[str, str], ...] = (
    {
        "User-Agent": BROWSER_UAS[0],   # Chrome 124 / Windows
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "User-Agent": BROWSER_UAS[1],   # Firefox 125 / Windows
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.7,en;q=0.6",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "User-Agent": BROWSER_UAS[2],   # Safari 17.4 / macOS
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
)

# 非 document 请求（API/静态资源）剥离的导航语义头部
_NAV_ONLY_HEADERS: tuple[str, ...] = ("Sec-Fetch-User", "Upgrade-Insecure-Requests")


def session_profile(session_id: str, *, purpose: str = "document") -> dict[str, str]:
    """按 session_id 确定性选择一个完整头部档案（会话内稳定、跨会话轮换）。

    - purpose="document"  完整档案（导航请求）；
    - purpose="resource"  剥离导航语义头部（Sec-Fetch-User 等），语义保持一致。
    HARD：仅返回白名单档案，任何调用方附加的可识别头部由 egress 层之外的
    scope 检查负责；本模块不透传自定义 UA。
    """
    if not session_id:
        # 无会话上下文：退化为每请求随机 UA（与历史 stealth.random_user_agent 行为一致）
        import random
        seed = random.choice(_PROFILE_SEEDS)
    else:
        digest = hashlib.sha256(f"anon-profile:{session_id}".encode("utf-8")).digest()
        seed = _PROFILE_SEEDS[digest[0] % len(_PROFILE_SEEDS)]
    profile = dict(seed)
    if purpose != "document":
        for key in _NAV_ONLY_HEADERS:
            profile.pop(key, None)
    return profile


def apply_profile(headers: dict[str, str] | None, session_id: str,
                  *, purpose: str = "document") -> dict[str, str]:
    """把档案合并进调用方头部（档案键优先，调用方 Cookie 等业务键保留）。"""
    merged = dict(headers or {})
    for key, value in session_profile(session_id, purpose=purpose).items():
        merged[key] = value
    return merged


def request_headers(*, purpose: str = "document") -> dict[str, str]:
    """统一请求头部入口（HARD：所有出站 HTTP 调用方使用本函数）。

    - 匿名启用 → 进程级稳定完整档案（会话内一致，跨运行轮换）；
    - 匿名关闭 → 仅随机常见浏览器 UA（与历史 stealth 行为完全一致）。
    """
    import random
    from security.anonymity.egress import is_anonymity_enabled
    if is_anonymity_enabled():
        return session_profile(default_session_id(), purpose=purpose)
    return {"User-Agent": random.choice(BROWSER_UAS)}
