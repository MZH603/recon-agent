"""共享 HTTP 出口助手（HARD: scheme 白名单 + 浏览器 UA + 403 答案 + 统一错误收敛）。

全部工具的出站 HTTP 请求统一走此模块，消除 5 处重复的 UA/超时/错误处理逻辑。
匿名层：security/anonymity.egress 统一注入代理路由；未启用时行为与历史一致。
"""
from __future__ import annotations

import http.client
import time
import urllib.error
import urllib.request

from security.anonymity.egress import (
    AnonymityRequiredError,
    build_opener,
    report_egress_failure,
    report_egress_success,
)
from security.anonymity.fingerprint import request_headers


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
    - 连接失败 → (0, {}, "")（匿名 kill-switch 触发时同样收敛为无答案，不泄露直连行为）
    HARD: 仅允许 http(s) scheme 出站；匿名启用时请求必须经配置出口。
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"仅允许 http(s) URL: {url[:60]}")
    req = urllib.request.Request(url, headers=request_headers())
    try:
        started = time.monotonic()
        opener = build_opener(insecure=insecure)  # 匿名启用=经出口；未启用=直连（历史行为）
        with opener.open(req, timeout=timeout) as resp:
            report_egress_success((time.monotonic() - started) * 1000.0)
            return resp.status, dict(resp.headers), resp.read(max_bytes).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        # 4xx/5xx 是有效答案，不是失败（出口本身工作正常）
        report_egress_success()
        try:
            body = exc.read(max_bytes).decode("utf-8", errors="replace")
        except (OSError, ValueError, http.client.HTTPException):
            body = ""
        return exc.code, dict(exc.headers or {}), body
    except AnonymityRequiredError:
        # HARD: kill-switch 拒绝出站 → 收敛为「无答案」，绝不降级直连
        return 0, {}, ""
    except (OSError, ValueError, http.client.HTTPException):
        # HARD: 截断响应（IncompleteRead）与连接错误统一收敛为「无答案」，不向上抛异常；
        # 匿名启用时该出口进入冷却（防死出口反复撞墙）
        report_egress_failure()
        return 0, {}, ""


def http_get_text(url: str, timeout: int = 10, insecure: bool = False,
                  max_bytes: int = 200_000) -> str:
    """便捷封装：返回响应体文本（连接失败返回空串）。"""
    _, _, body = http_get(url, timeout, insecure, max_bytes)
    return body
