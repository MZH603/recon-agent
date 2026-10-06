"""敏感路径字典 + 信息泄露签名库（内容级嗅探，WhatWeb/trufflehog 式思路）。

HARD：签名只来自真实泄露形态；匹配结果必须带证据（原始响应哈希）进入报告，
禁止"疑似"当"确认"——High 级发现需人工复核后方可对外定性。
"""
from __future__ import annotations

import re

# ---- 信息泄露签名（响应体内容级分析）----
# (正则, 泄露类型, 级别)
LEAK_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥文件内容", "High"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "High"),
    (r"ref:\s*refs/(heads|remotes)/", "Git 仓库元数据（.git 可读）", "High"),
    (r"\[core\]\s", "Git 配置文件（.git/config）", "High"),
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{16,}",
     "疑似 API 密钥/令牌", "High"),
    (r"(?i)(db_|database_)?pass(word|wd)\s*[=:]\s*[\"']?[^\s\"']{6,}", "疑似口令泄露", "High"),
    (r"(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s\"']{6,}", "数据库连接串", "High"),
    (r"Index of /", "目录列表开启", "Medium"),
    (r"phpinfo\(\)|PHP Version \d+\.\d+", "phpinfo 信息页", "Medium"),
    (r"ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.", "JWT 令牌", "Medium"),
    (r"at [\w$.]+\([\w$.]+\.java:\d+\)", "Java 堆栈泄露", "Medium"),
    (r"Spring Boot.*Actuator|\"_links\"\s*:", "Actuator 端点内容", "Info"),
    (r"Warning</b>:.* in <b>/", "PHP 错误路径泄露", "Low"),
    # CMS 版本泄露（CHANGELOG.txt 等内容）
    (r"Drupal \d+\.\d+", "Drupal 版本泄露", "High"),
    (r"WordPress (\d+\.\d+(?:\.\d+)?)", "WordPress 版本泄露", "High"),
    (r"Joomla! (\d+\.\d+(?:\.\d+)?)", "Joomla 版本泄露", "High"),
)

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def sniff_leaks(body: str) -> list[dict]:
    """纯函数：响应体泄露签名匹配 → [{type, severity}]（同类去重、按级别排序）。"""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for pattern, leak_type, severity in LEAK_SIGNATURES:
        if re.search(pattern, body):
            key = (leak_type, severity)
            if key not in seen:
                seen.add(key)
                out.append({"type": leak_type, "severity": severity})
    out.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 9))
    return out


def worst_severity(leaks: list[dict]) -> str:
    """取泄露列表中的最高级别（空列表 = Info）。"""
    return leaks[0]["severity"] if leaks else "Info"


# ---- 敏感路径字典（按优先级排序，合并后受 max_paths 截断）----
# 环境与配置（最高价值）→ CMS 版本泄露 → CMS 登录面 → 中间件管理面 →
# 备份文件 → 信息页 → API → 标准文件 → CMS 框架路径
DEFAULT_PATHS: tuple[str, ...] = (
    # 环境与配置
    "/.env", "/.env.bak", "/.git/HEAD", "/.git/config",
    "/.svn/entries", "/.aws/credentials", "/web.config",
    "/config.php.bak", "/settings.php", "/wp-config.php.bak",
    "/sites/default/settings.php",
    # CMS 版本泄露
    "/CHANGELOG.txt", "/composer.json", "/package.json",
    "/README.txt", "/UPDATE.txt", "/MAINTAINERS.txt", "/LICENSE.txt",
    # CMS 登录面
    "/admin", "/admin/", "/login", "/user/login", "/user/register",
    "/administrator/", "/wp-login.php", "/wp-admin/", "/manager/html",
    # 中间件管理面
    "/phpmyadmin", "/adminer.php", "/druid", "/jmx-console/",
    "/actuator", "/actuator/env", "/actuator/health", "/swagger-ui.html",
    # Drupal 特有
    "/cron.php", "/xmlrpc.php", "/install.php", "/update.php",
    "/node", "/node/1", "/user/password",
    "/sites/default/files/",
    # 备份文件
    "/backup", "/backup.zip", "/site.zip", "/web.zip",
    "/db.sql", "/dump.sql", "/database.sql", "/backup.sql",
    "/index.bak", "/login.bak",
    # 信息页
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    # API
    "/api", "/api/", "/graphql", "/graphql/playground",
    # 标准文件
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.DS_Store", "/.htaccess", "/.htpasswd", "/id_rsa",
    "/.htaccess.bak", "/cgi-bin/", "/drupal",
    # 通用 CMS 路径
    "/console", "/debug", "/test",
)

MAX_PATHS = 80  # HARD: 合并后探测路径上限（禁爆破）


# ---- CMS 感知路径生成 ----
CMS_SPECIFIC_PATHS: dict[str, tuple[str, ...]] = {
    "drupal": (
        "/user/login", "/user/reset/1", "/cron.php", "/xmlrpc.php",
        "/install.php", "/update.php", "/admin/config", "/admin/people",
        "/node/1", "/node/2", "/sites/default/files/", "/profiles/standard/",
        "/CHANGELOG.txt", "/README.txt", "/MAINTAINERS.txt",
    ),
    "wordpress": (
        "/wp-json/wp/v2/users", "/wp-json/", "/wp-content/debug.log",
        "/xmlrpc.php", "/wp-includes/version.php", "/readme.html",
    ),
    "joomla": (
        "/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml",
        "/components/com_users/", "/images/",
    ),
}


def cms_aware_paths(cms_name: str) -> tuple[str, ...]:
    """根据已识别 CMS 生成补充路径（纯函数）。"""
    cms_lower = cms_name.lower()
    for key, paths in CMS_SPECIFIC_PATHS.items():
        if key in cms_lower:
            return paths
    return ()


def classify_response(path: str, status: int, body: str) -> dict | None:
    """单路径发现分级（纯函数）：泄露内容 > 存在需认证 > 可访问。"""
    if status not in (200, 401, 403):
        return None
    if status == 200:
        leaks = sniff_leaks(body)
        severity = worst_severity(leaks)
        note = "、".join(f"{l['type']}({l['severity']})" for l in leaks) or "可访问（未见泄露内容）"
        return {"path": path, "status": status, "severity": severity,
                "leaks": leaks, "note": note}
    return {"path": path, "status": status, "severity": "Medium", "leaks": [],
            "note": {401: "存在(需认证)", 403: "存在(禁止)"}[status]}
