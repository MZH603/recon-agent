"""MCP stdio → 真实守卫链/HTTP 采集 → 协议结果及审计文件。"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest

pytestmark = pytest.mark.e2e


def rpc(identifier, method, **params):
    return {"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}


def exchange(run_app, messages, *, cli=False, allow_l1=False):
    args = ["--authorized-for", "127.0.0.1"]
    if allow_l1:
        args.append("--allow-l1")
    if cli:
        args.insert(0, "--mcp")
    result = run_app(*args, module="cli.main" if cli else "server.mcp_server",
                     input_text="".join(json.dumps(item) + "\n" for item in messages))
    assert result.returncode == 0, result.stdout + result.stderr
    frames = [json.loads(line) for line in result.stdout.splitlines()]
    assert [frame["id"] for frame in frames] == [
        item["id"] for item in messages if "id" in item
    ]
    assert all(frame["jsonrpc"] == "2.0" for frame in frames)
    return frames


@pytest.mark.parametrize("cli", [False, True], ids=["standalone", "cli"])
def test_mcp_handshake_catalog_and_policy(run_app, cli):
    frames = exchange(run_app, [
        rpc(1, "initialize", protocolVersion="2024-11-05"),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        rpc(2, "ping"),
        rpc(3, "tools/list"),
        rpc(4, "tools/call", name="recon_safety_policy", arguments={}),
    ], cli=cli)
    assert frames[0]["result"]["serverInfo"]["name"] == "recon-agent"
    assert frames[1]["result"] == {}
    names = {item["name"] for item in frames[2]["result"]["tools"]}
    assert {"fingerprint", "recon_safety_policy"} <= names
    assert frames[3]["result"]["isError"] is False
    assert "L2" in frames[3]["result"]["content"][0]["text"]


@pytest.mark.parametrize(("tool", "arguments", "reason", "allow_l1"), [
    ("fingerprint", {"target": "outside.invalid"}, "[范围拦截]", False),
    ("nmap_scan", {"target": "127.0.0.1", "ports": "80"}, "[门控]", False),
    ("dir_enum", {"target": "127.0.0.1"}, "[门控]", True),
])
def test_mcp_rejects_scope_and_level_bypass(run_app, tool, arguments, reason, allow_l1):
    frame = exchange(run_app, [rpc(1, "tools/call", name=tool, arguments=arguments)],
                     allow_l1=allow_l1)[0]
    assert frame["result"]["isError"] is True
    assert reason in frame["result"]["content"][0]["text"]


def test_mcp_fingerprint_collects_local_http_evidence(run_app, tmp_path):
    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx/1.24.0"
        sys_version = ""

        def do_GET(self):
            body = (b"User-agent: *\nDisallow: /wp-admin/\n" if self.path == "/robots.txt"
                    else b'<html><head><title>E2E fixture</title>'
                         b'<meta name="generator" content="WordPress 6.4.2"></head>'
                         b'<body id="wp-content">local fixture</body></html>')
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        frame = exchange(run_app, [rpc(1, "tools/call", name="fingerprint",
                                      arguments={"target": target})])[0]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    result = frame["result"]
    assert result["isError"] is False, result
    payload = json.loads(result["content"][0]["text"])
    assert payload["success"] is True
    assert payload["data"]["title"] == "E2E fixture"
    assert payload["data"]["tech"]["server"]["name"] == "Nginx"
    assert payload["data"]["tech"]["generator"]["version"] == "6.4.2"
    assert len(payload["source_hash"]) == 64
    assert payload["evidence"]
    audit = tmp_path / "config" / "recon-agent" / "audit.log"
    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert any(record["event"] == "mcp_server_start"
               and record["payload"]["roots"] == ["127.0.0.1"] for record in records)
    assert all(len(record["hash"]) == 64 for record in records)
