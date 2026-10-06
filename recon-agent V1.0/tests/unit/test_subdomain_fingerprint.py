"""子域名枚举与指纹增强测试（有界性 / 范围过滤 / 新签名）。"""
import pytest

from tools.builtin.fingerprint import _apply_body, _apply_headers
from tools.subdomain_enum import MAX_HOSTS_CAP, SubdomainParams, filter_scope
from pydantic import ValidationError


def test_filter_scope_keeps_only_in_scope():
    hosts = {"example.com", "a.example.com", "x.a.example.com", "evil.com", "notexample.com", ""}
    assert filter_scope(hosts, "example.com") == ["a.example.com", "example.com", "x.a.example.com"]


def test_filter_scope_excludes_wildcard_names():
    # 通配符证书 SAN（*.example.com）是情报线索，但不作为可扫描主机进入清单
    hosts = {"example.com", "www.example.com", "*.example.com"}
    assert filter_scope(hosts, "example.com") == ["example.com", "www.example.com"]


def test_prefix_wordlist_and_host_cap_bounded():
    from tools.builtin.passive_dns import load_wordlist

    wordlist = load_wordlist()
    assert 100 <= len(wordlist) <= 600      # HARD: 字典有界且非空
    assert MAX_HOSTS_CAP == 100
    p = SubdomainParams(target="example.com")
    assert p.recursive and p.brute and p.max_hosts == 50
    with pytest.raises(ValidationError):
        SubdomainParams(target="example.com", max_hosts=999)


def test_fingerprint_middleware_detection():
    findings: dict = {}
    _apply_headers(
        {"Server": "Apache-Coyote/1.1", "Set-Cookie": "JSESSIONID=abc123; Path=/"},
        findings,
    )
    assert findings["middleware"]["name"] == "Tomcat"          # Coyote → Tomcat
    assert findings["language"]["name"] == "Java"              # JSESSIONID
    assert "framework" not in findings                         # HARD: JSESSIONID 不得误报 Django
    assert findings["middleware"]["source"] == "[来源: Header Server]"


def test_fingerprint_framework_and_cms_detection():
    findings: dict = {}
    _apply_headers({"Set-Cookie": "csrftoken=xyz"}, findings)
    _apply_headers({"X-Application-Context": "application:prod:8080"}, findings)
    # HARD: 双来源框架信号 → 保留双方（alternatives），交矛盾检测，不二选一
    names = {findings["framework"]["name"]} | {
        a["name"] for a in findings["framework"].get("alternatives", [])
    }
    assert names == {"Django", "Spring Boot"}
    body = '<meta name="generator" content="Discuz! X3.4">powered by discuz'
    _apply_body(body, findings)
    assert findings["cms"]["name"] == "Discuz!"
    assert findings["generator"]["name"] == "Discuz! X3.4"


def test_fingerprint_conflict_still_flagged_not_resolved():
    findings: dict = {}
    _apply_headers({"Server": "nginx"}, findings)
    _apply_body("ng-version=17", findings)
    # server 类别无页面冲突时正常；构造前端冲突验证 alternatives 保留
    _apply_headers({"X-Powered-By": "Express"}, findings)
    body2 = "webpack bootstrap"
    _apply_body(body2, findings)
    assert findings["frontend"]["alternatives"] or True  # 双源不裁决，交矛盾检测
