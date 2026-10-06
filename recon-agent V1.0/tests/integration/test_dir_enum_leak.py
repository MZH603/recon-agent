"""dir_enum 哨兵与泄露嗅探集成测试（本地靶场实弹）。"""
import asyncio
import http.server
import threading

from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from tools.dir_enum import DirEnumParams, DirEnumTool
from utils.config import Settings


class _LeakHandler(http.server.BaseHTTPRequestHandler):
    """预置泄露内容的本地靶场：/.env 假密钥 + /.git/HEAD。"""

    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self):  # noqa: N802
        bodies = {
            "/.env": b"DB_PASSWORD=Sup3rS3cret!\nAPI_KEY=abcdefgh1234567890abcdef",
            "/.git/HEAD": b"ref: refs/heads/main",
            "/": b"<html><title>Lab</title></html>",
        }
        body = bodies.get(self.path, b"<html>404</html>")
        self.send_response(200 if self.path in bodies else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a) -> None:  # 静默
        pass


def _make_tool_and_server(settings: Settings = None):
    settings = settings or Settings()
    settings.LAB_MODE = True
    settings.REQUEST_DELAY_RANGE = (0.0, 0.0)  # 测试提速（生产默认 3-10s）
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LeakHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tool = DirEnumTool(settings, delay_range=(0.0, 0.0))
    return tool, server, server.server_address[1]


def test_scheme_pick_skips_broken_https():
    """哨兵回归：https 握手失败必须返回 -1 并降级 http（曾因 !=0 误判 https 可用）。"""
    tool, server, port = _make_tool_and_server()
    try:
        scheme = asyncio.run(tool._pick_scheme(f"127.0.0.1:{port}"))
        assert scheme == "http"
        status, _ = asyncio.run(
            asyncio.to_thread(tool._get_response, f"https://127.0.0.1:{port}/.env"))
        assert status == -1
    finally:
        server.shutdown()


def test_leak_sniffing_live_on_fixture():
    """泄露嗅探实弹：假 .env/.git 必须判 High 并带证据哈希。"""
    settings = Settings()
    settings.LAB_MODE = True  # HARD: 127.0.0.1 内网目标需 --lab（自有靶场）
    settings.REQUEST_DELAY_RANGE = (0.0, 0.0)  # 测试提速
    tool, server, port = _make_tool_and_server(settings)
    try:
        gate = ScanGate("127.0.0.1", batch_mode=False, is_tty=True, requested_level=2)
        gate.unlock_level_2()  # 测试注入：等效三次确认已完成

        async def yes(_prompt: str) -> str:
            return "yes"

        gate._prompt_fn = yes

        async def _run():
            from tools.registry import build_default

            registry = build_default(settings, gate, "127.0.0.1")
            return await registry.execute(NormalizedToolCall(
                id="t", name="dir_enum",
                arguments={"target": f"127.0.0.1:{port}",
                           "paths": ["/.env", "/.git/HEAD", "/admin"],
                           "max_paths": 3}))

        result = asyncio.run(_run())
        assert result.success, result.error
        found = {f["path"]: f for f in result.data["found"]}
        assert found["/.env"]["severity"] == "High"
        assert any(l["type"] == "疑似口令泄露" for l in found["/.env"]["leaks"])
        assert found["/.git/HEAD"]["severity"] == "High"
        assert found["/.git/HEAD"]["hash"]           # 证据哈希（HARD）
        assert result.data["high_count"] == 2
    finally:
        server.shutdown()
