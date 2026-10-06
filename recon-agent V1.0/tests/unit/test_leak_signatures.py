"""泄露签名库测试（内容级嗅探）。"""
from tools.builtin.leak_signatures import sniff_leaks, worst_severity


def test_env_file_leak_detected():
    body = "DB_PASSWORD=Sup3rS3cret!\nAPI_KEY=abcdefgh1234567890abcdef"
    leaks = sniff_leaks(body)
    assert any(l["type"] == "疑似口令泄露" and l["severity"] == "High" for l in leaks)
    assert any(l["type"] == "疑似 API 密钥/令牌" for l in leaks)
    assert worst_severity(leaks) == "High"


def test_git_metadata_leak():
    leaks = sniff_leaks("ref: refs/heads/master\n[core]\n")
    assert any(l["type"] == "Git 仓库元数据（.git 可读）" for l in leaks)


def test_private_key_and_connection_string():
    body = "-----BEGIN RSA PRIVATE KEY-----\nmysql://root:pw@db/x"
    leaks = sniff_leaks(body)
    assert any(l["type"] == "私钥文件内容" for l in leaks)
    assert any(l["type"] == "数据库连接串" for l in leaks)


def test_medium_and_info_levels():
    assert any(l["type"] == "目录列表开启" for l in sniff_leaks("Index of /backup"))
    assert any(l["type"] == "Actuator 端点内容" for l in sniff_leaks('{"_links":{"self":...}}'))


def test_clean_body_no_findings():
    assert sniff_leaks("<html><body>普通页面</body></html>") == []
    assert worst_severity([]) == "Info"


def test_dedup_same_type():
    body = "API_KEY=aaaa1111bbbb2222cccc\napi_key = dddd3333eeee4444ffff"
    leaks = sniff_leaks(body)
    api = [l for l in leaks if l["type"] == "疑似 API 密钥/令牌"]
    assert len(api) == 1  # 同类去重
