"""L3 工具纯函数单测：AXFR 报文 / 泛解析过滤 / vhost 差分 / cloud 分类 / banner 识别。"""
import struct

from tools.builtin.cloud_enum import bucket_candidates, classify_bucket_response
from tools.builtin.dir_enum_deep import build_bypass_variants, is_soft404
from tools.builtin.dns_enum import (
    build_query,
    encode_name,
    filter_wildcard,
    parse_response_records,
    permute_candidates,
)
from tools.builtin.service_banner import classify_banner
from tools.builtin.vhost_scan import diff_candidate

# ---------- dns_enum ----------


def test_encode_and_build_query():
    packet = build_query("example.com", 252, 0x1234)
    qid, flags, qd = struct.unpack(">HHH", packet[:6])
    assert qid == 0x1234 and flags == 0 and qd == 1
    assert packet.endswith(struct.pack(">HH", 252, 1))
    assert b"\x07example\x03com\x00" in packet
    assert encode_name("a.b") == b"\x01a\x01b\x00"


def _make_response(name: str, rtype: int, rdata: bytes, qname: str = "example.com") -> bytes:
    question = encode_name(qname) + struct.pack(">HH", rtype, 1)
    answer = encode_name(name) + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    return header + question + answer


def test_parse_response_records_a_record():
    buf = _make_response("www.example.com", 1, bytes([1, 2, 3, 4]))
    rcode, records = parse_response_records(buf)
    assert rcode == 0
    assert records[0]["name"] == "www.example.com"
    assert records[0]["typename"] == "A" and records[0]["value"] == "1.2.3.4"


def test_parse_response_records_refused():
    header = struct.pack(">HHHHHH", 1, 0x8185, 0, 0, 0, 0)  # rcode=5
    rcode, records = parse_response_records(header)
    assert rcode == 5 and records == []


def test_filter_wildcard():
    found = {"a.example.com": "1.1.1.1", "b.example.com": "9.9.9.9"}
    assert filter_wildcard(found, {"9.9.9.9"}) == {"a.example.com": "1.1.1.1"}
    assert filter_wildcard(found, set()) == found


def test_permute_candidates():
    cands = permute_candidates(["api.example.com"], "example.com", 100)
    assert "api-test.example.com" in cands and "dev-api.example.com" in cands
    assert len(cands) <= 100


# ---------- service_banner ----------


def test_classify_banner_ssh():
    entry = classify_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22)
    assert entry["service"] == "SSH" and entry["version"].startswith("OpenSSH")
    assert entry["confidence"] >= 0.9


def test_classify_banner_empty_port_hint():
    entry = classify_banner("", 6379)
    assert entry["service"] == "Redis?" and entry["confidence"] <= 0.3


# ---------- vhost_scan / dir_enum_deep ----------


def test_diff_candidate_verdicts():
    assert diff_candidate("h1", 100, "h1", 100) == "same-as-baseline"
    assert diff_candidate("h1", 100, "h2", 5000) == "distinct"
    assert diff_candidate("h1", 100, "h2", 105) == "similar-length"


def test_is_soft404():
    assert is_soft404("abc", 100, "abc", 100)
    assert is_soft404("abc", 100, "def", 108)  # 近似同长
    assert not is_soft404("abc", 100, "def", 999)


def test_build_bypass_variants():
    variants = build_bypass_variants("/admin")
    assert len(variants) == 2
    assert variants[1] == {"X-Original-URL": "/admin"}
    assert all("user-agent" not in {k.lower() for k in v} for v in variants)


# ---------- cloud_enum ----------


def test_bucket_candidates_cap_and_dedup():
    cands = bucket_candidates("example.com", 10)
    assert len(cands) == 10 and len(set(cands)) == 10


def test_classify_bucket_responses():
    assert classify_bucket_response(200, "<ListBucketResult>...")["severity"] == "High"
    assert classify_bucket_response(200, "hello")["verdict"] == "public_read"
    assert classify_bucket_response(403, "")["verdict"] == "exists_denied"
    assert classify_bucket_response(404, "NoSuchBucket")["verdict"] == "absent"
