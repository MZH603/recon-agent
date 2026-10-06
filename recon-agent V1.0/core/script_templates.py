"""LLM 临时脚本编写模板库（对标 WhatWeb / Nuclei / trufflehog 代码架构）。

Agent 生成临时探测脚本时，从此处获取专业模板作为骨架，
LLM 仅需替换目标特定的探测逻辑（匹配规则/路径列表/分析维度）。

HARD：模板仅使用标准库 · 内置限速 · 结构化输出 · 证据收集 · 用完即弃。
"""

# WhatWeb 式探测：多信号匹配（status + header + body + regex）
WHATWEB_PROBE = '''"""WhatWeb 式多信号探测（对标 WhatWeb 插件架构）。"""
import http.client
import hashlib
import json
import re
import time

__TARGET__ = "{target}"
MATCHES = [
    {{"status": 200, "search": "wp-content", "tech": "WordPress", "version_group": 0}},
    {{"status": 200, "search": "CHANGELOG.txt", "tech": "Drupal", "version_group": 0}},
    {{"search_header": "server", "regex": r"nginx/[\\\\d.]+", "tech": "Nginx"}},
]

def probe(path="/"):
    for _ in range(3):
        try:
            conn = http.client.HTTPSConnection(__TARGET__, timeout=10)
            conn.request("GET", path, headers={{"User-Agent": "Mozilla/5.0"}})
            resp = conn.getresponse()
            body = resp.read(100000).decode("utf-8", errors="replace")
            result = {{"path": path, "status": resp.status,
                       "headers": dict(resp.headers), "body": body}}
            conn.close()
            return result
        except Exception:
            time.sleep(3)
    return {{"path": path, "status": 0, "headers": {{}}, "body": ""}}

def match(response):
    findings = []
    for m in MATCHES:
        if "status" in m and response["status"] != m["status"]:
            continue
        if "search" in m and m["search"] in response.get("body", ""):
            findings.append(m["tech"])
        if "search_header" in m:
            val = response.get("headers", {{}}).get(m["search_header"], "")
            if re.search(m["regex"], val):
                findings.append(m["tech"])
    return findings

results = {{"target": __TARGET__, "probes": [], "findings": []}}
for p in ["/", "/robots.txt", "/admin", "/.env"]:
    r = probe(p)
    results["probes"].append(r)
    f = match(r)
    if f:
        results["findings"].extend(f)
    time.sleep(3)

body_hash = hashlib.sha256(json.dumps(results, sort_keys=True).encode()).hexdigest()[:64]
results["evidence_hash"] = body_hash
print(json.dumps(results, indent=2, ensure_ascii=False))
'''

# Nuclei 式模板扫描：结构化签名单独文件（对标 Nuclei YAML 模板架构）
NUCLEI_PROBE = '''"""Nuclei 式模板探测（签名与逻辑分离，对标 Nuclei YAML 模板）。"""
import http.client
import hashlib
import json
import time

__TARGET__ = "{target}"
# 签名模板（对标 Nuclei YAML：id / info / matchers / extractors）
TEMPLATES = [
    {{"id": "spring-actuator",
      "path": "/actuator",
      "matchers": [{{"type": "word", "words": ["_links"]}}],
      "extractors": [{{"type": "json", "json_path": "_links"}}],
      "severity": "info"}},
    {{"id": "env-exposure",
      "path": "/.env",
      "matchers": [{{"type": "regex", "regex": "^[A-Z]+="}}],
      "severity": "high"}},
    {{"id": "git-exposure",
      "path": "/.git/HEAD",
      "matchers": [{{"type": "word", "words": ["ref:"]}}],
      "severity": "high"}},
]

def scan(path, template):
    for _ in range(3):
        try:
            conn = http.client.HTTPSConnection(__TARGET__, timeout=10)
            conn.request("GET", path, headers={{"User-Agent": "Mozilla/5.0"}})
            resp = conn.getresponse()
            body = resp.read(100000).decode("utf-8", errors="replace")
            result = {{"status": resp.status, "headers": dict(resp.headers), "body": body}}
            conn.close()
            matched = all(
                (m["type"] == "word" and m["words"][0] in result["body"]) or
                (m["type"] == "regex" and __import__("re").search(m["regex"], result["body"]))
                for m in template["matchers"]
            )
            return {{"matched": matched, "severity": template["severity"],
                     "hash": hashlib.sha256(result["body"].encode()).hexdigest()[:32]}}
        except Exception:
            time.sleep(3)
    return {{"matched": False}}

results = []
for t in TEMPLATES:
    r = scan(t["path"], t)
    if r["matched"]:
        results.append({{"id": t["id"], "severity": r["severity"], "evidence": r["hash"]}})
    time.sleep(3)
print(json.dumps(results, indent=2, ensure_ascii=False))
'''

# 内容泄露嗅探（对标 trufflehog 密钥检测 + Lemma 数据泄露分类）
LEAK_SNIFF = '''"""内容泄露嗅探（对标 trufflehog 密钥检测 + 正则签名引擎）。"""
import re

SIGNATURES = [
    (r"AKIA[0-9A-Z]{{16}}", "AWS Access Key", "critical"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "私钥文件", "critical"),
    (r"(?:mysql|postgres|mongodb)://[^\\s]", "数据库连接串", "critical"),
    (r"(?i)(api[_-]?key|token)\\s*[=:]\\s*[\\w-]{{16,}}", "API 密钥", "high"),
    (r"ey[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.", "JWT 令牌", "medium"),
    (r"\\d+\\.\\d+\\.\\d+\\.\\d+", "内网 IP 泄露", "low"),
    (r"[\\w.+-]+@[\\w-]+\\.[\\w.]+", "邮箱地址", "info"),
]

def sniff(body):
    leaks = []
    for pattern, leak_type, severity in SIGNATURES:
        for m in re.finditer(pattern, body):
            leaks.append({{"type": leak_type, "severity": severity,
                           "match": m.group()[:40]}})
    return leaks

body = open("response.txt", encoding="utf-8").read()
print(json.dumps(sniff(body), indent=2, ensure_ascii=False))
'''

ALL_TEMPLATES = {
    "whatweb_probe": WHATWEB_PROBE,
    "nuclei_probe": NUCLEI_PROBE,
    "leak_sniff": LEAK_SNIFF,
}
