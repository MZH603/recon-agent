"""L3 本地 Fixture 集成测试（离线确定性）：dir_enum_deep 软404基线/403绕过 + vhost_scan 差分。

本地 ThreadingHTTPServer 靶场（127.0.0.1 随机端口），LAB_MODE 解锁环回目标（HARD 允许）。
"""
import asyncio
import http.server
import threading

from tools.builtin.dir_enum_deep import DirEnumDeepParams, DirEnumDeepTool
from tools.builtin.vhost_scan import VhostScanParams, VhostScanTool
from utils.config import Settings

SECRET_BODY = (b"-----BEGIN RSA PRIVATE KEY----- fake-fixture-content "
               b"MIIEpAIBAAKCAQAx-random-padding-for-length-distinction-0123456789")
ADMIN_BODY = b"<html>admin panel fixture</html>"
CATCHALL_BODY = b"<html>generic 404 page for anything unknown</html>"


class _L3FixtureHandler(http.server.BaseHTTPRequestHandler):
    """定向特征靶场：/admin/.env 命中、未知路径 catch-all、Host 轮换差分。"""

    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self):  # noqa: N802
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        if host == "hidden.example.test":
            body, status = ADMIN_BODY, 200
        elif self.path == "/admin":
            body, status = ADMIN_BODY, 200
        elif self.path == "/.env":
            body, status = SECRET_BODY, 200
        elif self.path == "/locked":
            body, status = b"403", 403
        else:
            body, status = CATCHALL_BODY, 200  # catch-all（软404 形态）

        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def _serve() -> tuple[http.server.ThreadingHTTPServer, int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _L3FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _settings() -> Settings:
    s = Settings()
    s.LAB_MODE = True  # HARD: 环回目标需 lab 模式
    # 测试提速：覆盖扰动延迟下界（生产默认 (2,5)，离线靶场无需真实节流）
    s.L3_DELAY_FLOOR = (0.02, 0.05)
    s.L3_DELAY_CEIL = (0.1, 0.2)
    return s


def test_dir_enum_deep_soft404_and_findings():
    server, port = _serve()
    try:
        tool = DirEnumDeepTool(_settings())
        result = asyncio.run(tool.run(DirEnumDeepParams(
            target=f"127.0.0.1:{port}", bypass_403=True, recurse=False,
            paths=["/admin", "/.env", "/locked"], max_paths=10)))
        assert result.success, result.error
        data = result.data
        found_paths = {f["path"] for f in data["found"]}
        assert "/admin" in found_paths and "/.env" in found_paths
        # catch-all 路径不应出现（软404 基线剔除）——/random-x 用例由递归关闭保证
        env = next(f for f in data["found"] if f["path"] == "/.env")
        assert env["severity"] == "High" and env.get("hash")
        # 403 绕过头变换：本靶场不看头，仅验证机制执行且不崩溃
        assert "bypass_403_hits" in data and "baseline" in data
        assert data["disturbance"]["requests"] >= 3  # 扰动台账存在
    finally:
        server.shutdown()


def test_vhost_scan_diff_finds_hidden_host():
    server, port = _serve()
    try:
        tool = VhostScanTool(_settings())
        result = asyncio.run(tool.run(VhostScanParams(
            target="127.0.0.1", port=port,
            candidates=["hidden.example.test", "plain.example.test"],
            use_wordlist=False)))
        assert result.success, result.error
        vhosts = {v["host"] for v in result.data["vhosts"]}
        assert "hidden.example.test" in vhosts           # 差分命中
        assert "plain.example.test" not in vhosts        # 与基线同哈希 → 不误报
    finally:
        server.shutdown()
