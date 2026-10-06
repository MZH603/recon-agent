"""MCP 服务器测试（协议 / 守卫链一致性 / stdio 端到端握手）。"""
import asyncio
import io
import json

from server.mcp_server import MCPProtocol
from server.tools_bridge import MCPBridge
from utils.config import get_settings


def make_protocol(roots=("example.com",), allow_l1=False) -> MCPProtocol:
    return MCPProtocol(MCPBridge(get_settings(), list(roots), allow_l1))


def test_initialize_negotiates_protocol_version():
    protocol = make_protocol()
    resp = asyncio.run(protocol.handle({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "claude", "version": "1"}}}))
    assert resp["result"]["protocolVersion"] == "2025-03-26"
    assert resp["result"]["serverInfo"]["name"] == "recon-agent"
    assert "tools" in resp["result"]["capabilities"]


def test_tools_list_exposes_schemas_and_policy():
    protocol = make_protocol()
    resp = asyncio.run(protocol.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"dns_query", "fingerprint", "httpx_probe", "nmap_scan",
            "recon_safety_policy"} <= names
    for tool in resp["result"]["tools"]:
        assert "inputSchema" in tool and "description" in tool


def test_notifications_return_none():
    protocol = make_protocol()
    assert asyncio.run(protocol.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"})) is None


def test_unknown_method_returns_32601():
    protocol = make_protocol()
    resp = asyncio.run(protocol.handle({"jsonrpc": "2.0", "id": 9, "method": "resources/list"}))
    assert resp["error"]["code"] == -32601


def test_ping():
    protocol = make_protocol()
    resp = asyncio.run(protocol.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"}))
    assert resp["result"] == {}


def test_call_scope_reject_outside_roots():
    # HARD: 外部 Agent 调用同样受范围硬拦截
    protocol = make_protocol(roots=("example.com",))
    resp = asyncio.run(protocol.handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "dns_query", "arguments": {"target": "evil.com"}}}))
    assert resp["result"]["isError"] is True
    assert "[范围拦截]" in resp["result"]["content"][0]["text"]


def test_call_gate_denies_l1_without_allow_l1():
    # HARD: MCP 未放行 L1 → nmap_scan 被门控拒绝
    protocol = make_protocol(roots=("example.com",), allow_l1=False)
    resp = asyncio.run(protocol.handle({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "nmap_scan",
                   "arguments": {"target": "sub.example.com", "ports": "80,443"}}}))
    assert resp["result"]["isError"] is True
    assert "[门控]" in resp["result"]["content"][0]["text"]


def test_call_schema_error_is_explicit():
    # Schema 校验失败显式回填（不猜测），错误可读
    protocol = make_protocol(roots=("example.com",))
    resp = asyncio.run(protocol.handle({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "dns_query", "arguments": {"target": "example.com", "rtype": "AXFR"}}}))
    assert resp["result"]["isError"] is True
    assert "参数校验失败" in resp["result"]["content"][0]["text"]


def test_policy_tool_returns_text():
    protocol = make_protocol()
    resp = asyncio.run(protocol.handle({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "recon_safety_policy", "arguments": {}}}))
    assert resp["result"]["isError"] is False
    assert "安全策略" in resp["result"]["content"][0]["text"]


def test_stdio_end_to_end_handshake(monkeypatch, capsys):
    # 端到端：initialize → tools/list，经真实 serve() 循环（EOF 退出）
    from server import mcp_server

    frames = "\n".join([
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        "",
    ])
    monkeypatch.setattr(mcp_server.sys, "stdin", io.StringIO(frames))
    ret = asyncio.run(mcp_server.serve(["example.com"], allow_l1=False))
    assert ret == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 2  # 通知不回应（HARD：协议帧纯净）
    hello = json.loads(out[0])
    assert hello["result"]["serverInfo"]["version"] == "1.0.0"
    tools = json.loads(out[1])
    assert any(t["name"] == "dns_query" for t in tools["result"]["tools"])
