"""情报扩容工具单测（P-A2/A3/A4/A5）：纯函数，零网络。"""
from tools.builtin.code_leak_search import (
    build_dorks,
    mask_secret,
    scan_secret_signatures,
)
from tools.builtin.dork_search import parse_baidu, parse_ddg, render_dorks, DorkTemplates
from tools.builtin.org_intel import OrgIntelTool
from tools.builtin.wayback_urls import extract_params

# ---------- A2: code_leak_search ----------


def test_mask_secret_never_contains_secret():
    secret = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(secret)
    assert secret not in masked
    assert masked.startswith("AKIA***")
    # 指纹部分固定 12 位（可复现比对，不可还原原文）


def test_scan_signatures_finds_and_masks():
    text = 'aws_key = "AKIAIOSFODNN7EXAMPLE"\ndb_pass = "hunter2secret"'
    findings = scan_secret_signatures(text)
    types = {f["type"] for f in findings}
    assert "AWS Access Key" in types and "疑似口令" in types
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f["masked"]
        assert "hunter2secret" not in f["masked"]
        assert f["masked"].endswith(")")  # sha256 指纹括号


def test_scan_signatures_dedup():
    text = "api_key=AAAAAAAAAAAAAAAAAAAA\napi_key=AAAAAAAAAAAAAAAAAAAA"
    findings = scan_secret_signatures(text)
    assert len([f for f in findings if f["type"] == "API Key/Token"]) == 1


def test_build_dorks_contains_domain():
    dorks = build_dorks("example.com")
    assert dorks and all("example.com" in d for d in dorks)
    assert any("filename:.env" in d for d in dorks)


# ---------- A4: dork_search ----------


def test_render_dorks():
    templates = DorkTemplates([
        {"query": "site:{domain} filetype:sql", "intent": "db", "severity": "High"}])
    rendered = render_dorks("example.com", templates)
    assert rendered == [("site:example.com filetype:sql", "db", "High")]


def test_parse_ddg_redirect_restore():
    html = ('<a rel="nofollow" class="result__a" '
            'href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.example.com%2Fsecret.sql&rut=abc">'
            'Result <b>Title</b></a>')
    hits = parse_ddg(html)
    assert hits[0]["url"] == "https://www.example.com/secret.sql"
    assert hits[0]["title"] == "Result Title"


def test_parse_baidu_redirect_recorded():
    html = '<h3 class="t"><a href="http://www.baidu.com/link?url=xyz">Some Page</a></h3>'
    hits = parse_baidu(html)
    assert hits[0]["url"].startswith("http://www.baidu.com/link")
    assert hits[0]["title"] == "Some Page"


# ---------- A3: org_intel ----------


def test_extract_emails_filters_noise_and_marks_scope():
    tool = OrgIntelTool.__new__(OrgIntelTool)  # 纯函数通道，不触发网络
    text = ("联系 admin@example.com 或 hr@example.com；"
            "第三方 sentry@a.sentry.io 与 noise@example.org 不算")
    emails = tool._extract_emails(text, "example.com")
    lowered = [e.lower() for e in emails]
    assert "admin@example.com" in lowered and "hr@example.com" in lowered
    assert not any(e.endswith("sentry.io") for e in lowered)
    assert not any(e.endswith("example.org") for e in lowered)


# ---------- A5: wayback params ----------


def test_extract_params():
    per_path, names = extract_params([
        "https://www.example.com/item?id=3&ref=x",
        "https://www.example.com/item?id=9&page=2",
        "https://www.example.com/static/app.js",
    ])
    assert set(per_path["https://www.example.com/item"]) == {"id", "page", "ref"}
    assert names == ["id", "page", "ref"]


def test_extract_params_empty():
    assert extract_params(["https://a.com/x", "https://a.com/y?"]) == ({}, [])
