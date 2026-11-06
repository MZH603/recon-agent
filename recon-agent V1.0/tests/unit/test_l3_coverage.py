"""L3 补全工具纯函数单测：PTR 反查 / 存活+OS / 拓扑追踪 / 参数挖掘 / 初步脆弱面 / 云平台扩展 / sitemap 收割。"""
from tools.builtin.alive_os_probe import parse_ping_output, ttl_to_os
from tools.builtin.cloud_enum import bucket_candidates, classify_bucket_response
from tools.builtin.dir_enum_deep import extract_sitemap_paths
from tools.builtin.nmap_tool import NmapL3Params
from tools.builtin.param_mining import (
    PARAM_NAMES,
    build_probe_url,
    detect_reflection,
    diff_param,
)
from tools.builtin.reverse_dns import build_ptr_name, extract_ptr, in_scope_hit
from tools.builtin.surface_check import (
    CORS_PROBE_ORIGIN,
    audit_security_headers,
    classify_cors,
    classify_tls_cert,
)
from tools.builtin.topology_trace import parse_tracert_windows, parse_traceroute_unix

# ---------- reverse_dns ----------


def test_build_ptr_name():
    assert build_ptr_name("93.184.216.34") == "34.216.184.93.in-addr.arpa"
    assert build_ptr_name("999.1.1.1") == ""
    assert build_ptr_name("not-an-ip") == ""
    assert build_ptr_name("") == ""


def test_extract_ptr():
    assert extract_ptr({"Answer": [{"type": 12, "data": "www.example.com."}]}) == \
        ["www.example.com"]
    assert extract_ptr({"Answer": [{"type": 1, "data": "1.2.3.4"}]}) == []
    assert extract_ptr({}) == []
    # 去重
    assert extract_ptr({"Answer": [
        {"type": 12, "data": "a.example.com."},
        {"type": 12, "data": "a.example.com"}]}) == ["a.example.com"]


def test_in_scope_hit():
    assert in_scope_hit(["api.example.com", "other.net"], "example.com") == ["api.example.com"]
    assert in_scope_hit(["example.com"], "example.com") == ["example.com"]
    assert in_scope_hit(["notexample.com"], "example.com") == []  # 后缀必须带点


# ---------- alive_os_probe ----------


def test_parse_ping_output_windows():
    alive, ttl = parse_ping_output(
        "Reply from 93.184.216.34: bytes=32 time=12ms TTL=128")
    assert alive and ttl == 128
    assert ttl_to_os(ttl) == "Windows（TTL≤128）"


def test_parse_ping_output_linux():
    alive, ttl = parse_ping_output(
        "64 bytes from 93.184.216.34: icmp_seq=1 ttl=64 time=1.23 ms")
    assert alive and ttl == 64
    assert ttl_to_os(ttl).startswith("Unix-like")


def test_parse_ping_output_timeout():
    alive, ttl = parse_ping_output("Request timed out.")
    assert not alive and ttl == 0
    alive, ttl = parse_ping_output("100% packet loss")
    assert not alive and ttl == 0


def test_ttl_to_os_ranges():
    assert ttl_to_os(64) == "Unix-like（TTL≤64）"
    assert ttl_to_os(1) == "Unix-like（TTL≤64）"
    assert ttl_to_os(65) == "Windows（TTL≤128）"
    assert ttl_to_os(128) == "Windows（TTL≤128）"
    assert ttl_to_os(129) == "网络设备（TTL≤255）"
    assert ttl_to_os(255) == "网络设备（TTL≤255）"
    assert ttl_to_os(0) == "未知"


# ---------- topology_trace ----------

WIN_TRACERT = """\r
Tracing route to example.com [93.184.216.34]\r
over a maximum of 30 hops:\r
\r
  1     1 ms    1 ms    1 ms  192.168.1.1\r
  2     *        *        *     Request timed out.\r
  3    12 ms   11 ms   12 ms  93.184.216.34\r
"""


def test_parse_tracert_windows():
    hops = parse_tracert_windows(WIN_TRACERT, 15)
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0]["addr"] == "192.168.1.1" and hops[0]["rtt_ms"] == 1
    assert hops[1]["timeout"] and hops[1]["addr"] == "timeout"
    assert hops[2]["addr"] == "93.184.216.34"


def test_parse_tracert_windows_hop_cap():
    assert parse_tracert_windows(WIN_TRACERT, 2)[0]["hop"] == 1


UNIX_TRACEROUTE = """traceroute to example.com (93.184.216.34), 15 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms
 2  * * *
 3  10.20.30.40  5.678 ms
"""


def test_parse_traceroute_unix():
    hops = parse_traceroute_unix(UNIX_TRACEROUTE, 15)
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0]["addr"] == "192.168.1.1" and abs(hops[0]["rtt_ms"] - 1.234) < 0.01
    assert hops[1]["timeout"] and hops[1]["addr"] == "timeout"
    assert hops[2]["addr"] == "10.20.30.40"


TRACEPATH_OUT = """ 1?:  [LOCALHOST]  pmtu 1500
 1:  192.168.1.1  0.5ms
 2:  no reply
 3:  93.184.216.34  12.3ms
"""


def test_parse_tracepath_format():
    hops = parse_traceroute_unix(TRACEPATH_OUT, 15)
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[1]["timeout"] and hops[1]["addr"] == "timeout"
    assert hops[2]["addr"] == "93.184.216.34"


# ---------- param_mining ----------


def test_detect_reflection():
    assert detect_reflection("<p>echo zmdeadbeef</p>", "zmdeadbeef")
    assert not detect_reflection("<p>normal</p>", "zmdeadbeef")
    assert not detect_reflection("anything", "")


def test_diff_param_verdicts():
    assert diff_param("h1", 100, "h1", 100) == "same-as-baseline"
    assert diff_param("h1", 100, "h2", 108) == "similar-length"  # 噪声带内
    assert diff_param("h1", 100, "h2", 5000) == "distinct"


def test_build_probe_url():
    assert build_probe_url("https://a.com/", "id", "m1") == "https://a.com/?id=m1"
    assert build_probe_url("https://a.com/?x=1", "q", "m2") == "https://a.com/?x=1&q=m2"


def test_param_names_no_injection_semantics():
    # 内置字典只含信息检索/分页/状态类名称，不含注入语义词
    assert "id" in PARAM_NAMES and len(PARAM_NAMES) >= 50
    assert all(" " not in p and "'" not in p for p in PARAM_NAMES)


# ---------- surface_check ----------


def test_audit_security_headers_missing():
    missing, cookies = audit_security_headers({"Server": "nginx"})
    names = {m["header"] for m in missing}
    assert {"Content-Security-Policy", "Strict-Transport-Security",
            "X-Frame-Options"} <= names
    assert cookies == []


def test_audit_security_headers_cookie_flags():
    _, cookies = audit_security_headers(
        {"Set-Cookie": "sid=abc; Path=/"})
    assert cookies and set(cookies[0]["missing_flags"]) == {"Secure", "HttpOnly", "SameSite"}
    _, cookies = audit_security_headers(
        {"Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"})
    assert cookies == []


def test_classify_cors_reflection():
    high = classify_cors(200, {"Access-Control-Allow-Origin": CORS_PROBE_ORIGIN,
                               "Access-Control-Allow-Credentials": "true"})
    assert high and high["severity"] == "High" and high["reflected"]
    med = classify_cors(200, {"Access-Control-Allow-Origin": CORS_PROBE_ORIGIN})
    assert med and med["severity"] == "Medium"
    wildcard = classify_cors(200, {"Access-Control-Allow-Origin": "*"})
    assert wildcard and wildcard["severity"] == "Low" and not wildcard["reflected"]
    assert classify_cors(200, {"Access-Control-Allow-Origin": "https://trusted.com"}) is None


def test_classify_tls_cert():
    assert classify_tls_cert({}) == []
    expired = classify_tls_cert({
        "notAfter": "Jan 01 00:00:00 2020 GMT",
        "subject": (("commonName", "example.com"),),
        "issuer": (("commonName", "Let's Encrypt"),),
    })
    assert any(f["type"] == "cert_expired" for f in expired)
    selfsigned = classify_tls_cert({
        "notAfter": "Jan 01 00:00:00 2100 GMT",
        "subject": (("commonName", "example.com"),),
        "issuer": (("commonName", "example.com"),),
    })
    assert any(f["type"] == "self_signed" for f in selfsigned)
    # 有效期内的正常证书：仅自签判定不命中
    ok = classify_tls_cert({
        "notAfter": "Jan 01 00:00:00 2100 GMT",
        "subject": (("commonName", "example.com"),),
        "issuer": (("commonName", "R3"),),
    })
    assert ok == []


# ---------- cloud_enum 扩展（Azure/GCS/OBS + 子域派生） ----------


def test_bucket_candidates_from_subdomains():
    cands = bucket_candidates("example.com", 100, ["api.example.com", "static.example.com"])
    assert "api" in cands and "api-static" in cands and "static" in cands
    assert "example-com" in cands  # 原有模板保留


def test_bucket_candidates_cap():
    assert len(bucket_candidates("example.com", 10, ["a.example.com"] * 50)) <= 10


def test_classify_azure_gcs():
    # Azure BlobNotFound / GCS NoSuchBucket XML 标记 → absent
    assert classify_bucket_response(404, "<?xml><Error><Code>BlobNotFound</Code>")["verdict"] == "absent"
    # Azure 匿名列举响应（<Blobs> 容器枚举）→ public_list
    azure_list = ("<?xml version=\"1.0\"?><EnumerationResults>"
                  "<Blobs><Blob><Name>f1.txt</Name></Blob></Blobs></EnumerationResults>")
    assert classify_bucket_response(200, azure_list)["verdict"] == "public_list"
    assert classify_bucket_response(200, "GCS object body")["verdict"] == "public_read"


# ---------- dir_enum_deep：sitemap 收割 ----------


def test_extract_sitemap_paths():
    body = ("<urlset><url><loc>https://a.com/admin/</loc></url>"
            "<url><loc>https://a.com/api/v1/users</loc></url>"
            "<url><loc>https://a.com/</loc></url>"
            "<url><loc>https://a.com/api/v1/users</loc></url></urlset>")
    paths = extract_sitemap_paths(body, cap=10)
    assert paths == ["/admin/", "/api/v1/users"]  # 首页剔除 + 去重


def test_extract_sitemap_paths_cap():
    body = "".join(f"<url><loc>https://a.com/p{i}</loc></url>" for i in range(50))
    assert len(extract_sitemap_paths(body, cap=5)) == 5


# ---------- nmap L3 os 模式 ----------


def test_nmap_l3_os_mode_params():
    params = NmapL3Params(target="example.com", scan_mode="os", ports="80,443")
    assert params.scan_mode == "os"
