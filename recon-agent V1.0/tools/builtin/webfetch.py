"""共享 HTTP 出口助手（HARD: scheme 白名单 + 浏览器 UA + 403 答案 + 统一错误收敛）。

全部工具的出站 HTTP 请求统一走此模块，消除 5 处重复的 UA/超时/错误处理逻辑。
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from security.stealth import random_user_agent


def http_get(
    url: str,
    timeout: int = 10,
    insecure: bool = False,
    max_bytes: int = 200_000,
) -> tuple[int, dict, str]:
    """共享同步 HTTP GET。

    返回 (status, headers, body)：
    - 2xx/3xx → 正常响应
    - 4xx/5xx → 有效答案（WhatWeb 式：403 页头部暴露 CDN/WAF 特征）
    - 连接失败 → (0, {}, "")
    HARD: 仅允许 http(s) scheme 出站。
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"仅允许 http(s) URL: {url[:60]}")
    req = urllib.request.Request(url, headers={"User-Agent": random_user_agent()})
    try:
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            resp_ctx = opener.open(req, timeout=timeout)
        else:
            resp_ctx = urllib.request.urlopen(req, timeout=timeout)
        with resp_ctx as resp:
            return resp.status, dict(resp.headers), resp.read(max_bytes).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # 4xx/5xx 是有效答案，不是失败
        try:
            body = exc.read(max_bytes).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            body = ""
        return exc.code, dict(exc.headers or {}), body
    except (OSError, ValueError):
        return 0, {}, ""


def http_get_text(url: str, timeout: int = 10, insecure: bool = False,
                  max_bytes: int = 200_000) -> str:
    """便捷封装：返回响应体文本（连接失败返回空串）。"""
    _, _, body = http_get(url, timeout, insecure, max_bytes)
    return body
