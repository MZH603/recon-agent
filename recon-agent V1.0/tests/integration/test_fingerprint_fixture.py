"""本地 Fixture 集成测试（P1-7）：指纹识别离线确定性验证 + 版本提取。"""
import asyncio
import http.server
import threading

from tools.builtin.fingerprint import FingerprintParams, FingerprintTool
from utils.config import Settings

FIXTURE_BODY = (
    b"<html><head><title>Fixture WP</title>"
    b'<meta name="generator" content="WordPress 6.4.2"></head>'
    b'<body><script src="/wp-includes/js/jquery/jquery-3.6.0.min.js"></script>'
    b"<div id='wp-content'>hello</div></body></html>"
)


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """预置 WordPress/Nginx 特征的本地靶场（仅监听 127.0.0.1 随机端口）。"""

    server_version = "nginx/1.24.0"  # 覆盖 BaseHTTP 默认 Server 头
    sys_version = ""

    def do_GET(self):  # noqa: N802 —— http.server 约定
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /wp-admin/\n"
        else:
            body = FIXTURE_BODY
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # 静默
        pass


def _serve() -> tuple[http.server.ThreadingHTTPServer, int]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def test_fingerprint_against_local_fixture():
    """对本地靶场做指纹识别：中间件版本 / CMS+版本 / JS 库版本 / title 全部命中。"""
    server, port = _serve()
    try:
        settings = Settings()
        settings.LAB_MODE = True  # HARD: 内网目标需 lab 模式（此处为本地 fixture）
        tool = FingerprintTool(settings, delay_range=(0.0, 0.0))
        result = asyncio.run(tool.run(FingerprintParams(target=f"127.0.0.1:{port}")))
        assert result.success, result.error
        tech = result.data["tech"]
        assert tech["server"]["name"] == "Nginx"
        assert tech["server"]["version"] == "1.24.0"          # 版本提取（Header）
        assert tech["cms"]["name"] == "WordPress"
        assert tech["generator"]["version"] == "6.4.2"        # 版本提取（generator）
        assert tech["js库"]["name"] == "jQuery"
        assert tech["js库"]["version"] == "3.6.0"             # 版本提取（script src）
        assert result.data["title"] == "Fixture WP"
        assert "/wp-admin/" in result.data["robots_hints"]
        assert result.source_hash                             # 证据绑定（HARD）
    finally:
        server.shutdown()
