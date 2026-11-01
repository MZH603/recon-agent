"""情报扩容数据源适配器单测（P-A1）：纯解析函数，零网络。"""
from tools.adapters.datasources import (
    HunterAdapter,
    NetlasAdapter,
    SecurityTrailsAdapter,
    VirusTotalAdapter,
    ADAPTERS,
)
from utils.config import Settings


def _adapter(cls):
    return cls(Settings(), api_key="dummy-key", api_secret="")


def test_new_adapters_registered():
    for name in ("hunter", "netlas", "virustotal", "securitytrails"):
        assert name in ADAPTERS


def test_hunter_parse():
    adapter = _adapter(HunterAdapter)
    url, headers, params = adapter._build_request('domain="example.com"', 1, 100)
    assert url == "https://hunter.qianxin.com/openApi/search"
    assert params["api-key"] == "dummy-key"
    assets = adapter._parse_response({
        "code": 200,
        "data": {"arr": [{"url": "https://www.example.com", "ip": "1.2.3.4",
                          "port": 443, "protocol": "https", "web_title": "Example"}]},
    }, "example.com")
    assert assets[0]["ip"] == "1.2.3.4" and assets[0]["source"] == "hunter"


def test_hunter_parse_rejects_error_code():
    assert _adapter(HunterAdapter)._parse_response({"code": 401}, "q") == []


def test_netlas_parse():
    adapter = _adapter(NetlasAdapter)
    assets = adapter._parse_response({
        "items": [{"ip": "5.6.7.8", "port": 443, "protocol": "https",
                   "data": {"results": {"host": "www.example.com",
                                        "http": {"title": "T", "server": "nginx"},
                                        "geo": {"org": "ACME", "city": "X"},
                                        "asn": {"number": 64512}}}}],
    }, "example.com")
    assert assets[0]["ip"] == "5.6.7.8" and assets[0]["asn"] == 64512
    assert assets[0]["title"] == "T"


def test_virustotal_request_path_and_parse():
    adapter = _adapter(VirusTotalAdapter)
    url, headers, params = adapter._build_request("example.com", 1, 100)
    assert url == "https://www.virustotal.com/api/v3/domains/example.com/subdomains"
    assert headers["x-apikey"] == "dummy-key"
    assert params["limit"] <= 40  # 免费额度收紧
    assets = adapter._parse_response({
        "data": [{"id": "www.example.com",
                  "attributes": {"id": "www.example.com",
                                 "last_dns_records": [{"value": "1.2.3.4"}]}}],
    }, "example.com")
    assert assets[0]["type"] == "subdomain" and assets[0]["value"] == "www.example.com"
    assert assets[0]["last_dns_records"] == ["1.2.3.4"]


def test_securitytrails_parse_prefix_and_history():
    adapter = _adapter(SecurityTrailsAdapter)
    url, headers, _ = adapter._build_request("example.com", 1, 100)
    assert url == "https://api.securitytrails.com/v1/domain/example.com/subdomains"
    assert headers["APIKEY"] == "dummy-key"
    assets = adapter._parse_response({
        "subdomains": ["www", "mail"],
        "records": [{"host": "example.com", "ips": ["9.9.9.9"],
                     "first_seen": "2020-01-01", "last_seen": "2021-01-01"}],
    }, "example.com")
    values = {a["value"] for a in assets}
    assert "www.example.com" in values and "mail.example.com" in values
    history = [a for a in assets if a["type"] == "dns_history"]
    assert history and history[0]["ips"] == ["9.9.9.9"]
