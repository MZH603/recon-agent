"""隧道原语测试：本地 mock HTTP CONNECT / SOCKS5 服务器验证握手与数据通路。"""
import asyncio
import socket
import threading

import pytest

from security.anonymity import tunnel
from security.anonymity.tunnel import TunnelError


def _read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("mock server: client closed early")
        buf += chunk
    return buf


def _echo_loop(conn: socket.socket) -> None:
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            conn.sendall(chunk)
    except OSError:
        pass
    finally:
        conn.close()


def _http_proxy_server(reject: bool = False) -> int:
    """mock HTTP 代理：CONNECT echo:1234 成功后进入字节回显；reject=True 返回 403。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += _read_exact(conn, 1)
        if reject:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            conn.close()
        else:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _echo_loop(conn)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def _socks5_server(require_auth: bool = False) -> int:
    """mock SOCKS5 服务器：问候 → 可选认证 → CONNECT(reply ATYP=domain) → 回显。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        head = _read_exact(conn, 2)
        methods = _read_exact(conn, head[1])
        if require_auth:
            if 0x02 not in methods:
                conn.sendall(b"\x05\xff")
                conn.close()
                srv.close()
                return
            conn.sendall(b"\x05\x02")
            ver, ulen = _read_exact(conn, 2)
            user = _read_exact(conn, ulen)
            plen = _read_exact(conn, 1)[0]
            password = _read_exact(conn, plen)
            if (user, password) != (b"u", b"p"):
                conn.sendall(b"\x01\x01")
                conn.close()
                srv.close()
                return
            conn.sendall(b"\x01\x00")   # 认证成功响应（RFC 1929）
        else:
            conn.sendall(b"\x05\x00")
        req = _read_exact(conn, 5)   # ver cmd rsv atyp dlen（ATYP=domain）
        assert req[3] == 0x03, "HARD: SOCKS5 必须使用 ATYP=domain 远端解析"
        host = _read_exact(conn, req[4])
        aport = _read_exact(conn, 2)
        reply = b"\x05\x00\x00\x03" + bytes([len(host)]) + host + aport
        conn.sendall(reply)
        _echo_loop(conn)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def _roundtrip(sock: socket.socket) -> bool:
    sock.sendall(b"ping")
    return _read_exact(sock, 4) == b"ping"


def test_socks5_connect_sync_roundtrip():
    """SOCKS5 握手成功后隧道可用（字节回显验证双向通路）。"""
    port = _socks5_server()
    sock = tunnel.socks5_connect_sync(f"socks5://127.0.0.1:{port}", "echo.example", 1234, timeout=5)
    assert _roundtrip(sock)
    sock.close()


def test_socks5_connect_sync_with_auth():
    """用户名/密码认证成功路径。"""
    port = _socks5_server(require_auth=True)
    sock = tunnel.socks5_connect_sync(f"socks5://u:p@127.0.0.1:{port}", "echo.example", 1234, timeout=5)
    assert _roundtrip(sock)
    sock.close()


def test_socks5_missing_credentials_rejected():
    """服务器要求认证而客户端未提供 → TunnelError（HARD：不降级直连）。"""
    port = _socks5_server(require_auth=True)
    with pytest.raises(TunnelError):
        tunnel.socks5_connect_sync(f"socks5://127.0.0.1:{port}", "echo.example", 1234, timeout=5)


def test_http_connect_sync_roundtrip():
    """HTTP CONNECT 隧道建立后字节回显验证。"""
    port = _http_proxy_server()
    sock = tunnel.http_connect_sync(f"http://127.0.0.1:{port}", "echo", 1234, timeout=5)
    assert _roundtrip(sock)
    sock.close()


def test_http_connect_rejected():
    """代理拒绝 CONNECT（403）→ TunnelError。"""
    port = _http_proxy_server(reject=True)
    with pytest.raises(TunnelError):
        tunnel.http_connect_sync(f"http://127.0.0.1:{port}", "echo", 1234, timeout=5)


def test_scheme_mismatch_rejected():
    """http_connect_sync 拒绝 socks5 URL（HARD：scheme 白名单不混用）。"""
    with pytest.raises(TunnelError):
        tunnel.http_connect_sync("socks5://127.0.0.1:1080", "echo", 1234, timeout=5)


def test_async_socks5_and_http_roundtrip():
    """asyncio 变体：SOCKS5 与 HTTP CONNECT 均可建隧道。"""

    async def run():
        r5, w5 = await tunnel.socks5_connect_async(
            f"socks5://127.0.0.1:{_socks5_server()}", "echo.example", 1234, timeout=5)
        w5.write(b"ping")
        await w5.drain()
        assert await r5.readexactly(4) == b"ping"
        w5.close()

        rh, wh = await tunnel.http_connect_async(
            f"http://127.0.0.1:{_http_proxy_server()}", "echo", 1234, timeout=5)
        wh.write(b"ping")
        await wh.drain()
        assert await rh.readexactly(4) == b"ping"
        wh.close()

    asyncio.run(run())


def test_tor_newnym_with_password():
    """Tor 控制端口：正确密码 → AUTHENTICATE 250 + SIGNAL NEWNYM 250 → True。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        f = conn.makefile("rwb")
        line = f.readline()
        if b'"secret"' in line:
            f.write(b"250 OK\r\n")
            f.flush()
            f.readline()          # SIGNAL NEWNYM
            f.write(b"250 OK\r\n")
            f.flush()
        else:
            f.write(b"515 Authentication failed\r\n")
            f.flush()
        f.close()
        conn.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    assert tunnel.tor_newnym("127.0.0.1", port, password="secret") is True
    assert tunnel.tor_newnym("127.0.0.1", port, password="wrong") is False


def test_tor_newnym_unreachable_returns_false():
    """控制端口不可达 → False（数据面不受影响，仅审计）。"""
    assert tunnel.tor_newnym("127.0.0.1", 1, password="x", timeout=1) is False


def test_http_connect_over_preserves_proxy_credentials():
    """BUG 回归：https 代理 scheme 改写时认证凭据不得丢失（_http_connect_over 收到 user/pass）。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += _read_exact(conn, 1)
        assert b"Proxy-Authorization: Basic" in data, "代理认证头必须在场"
        # base64("u:p") = dTpw
        assert b"dTpw" in data
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        _echo_loop(conn)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    tunnel._http_connect_over(sock, "127.0.0.1", port, "echo", 1234, "u", "p")
    sock.sendall(b"ping")
    assert _read_exact(sock, 4) == b"ping"
    sock.close()


def test_connect_sync_http_proxy_keeps_credentials():
    """connect_sync 对 http 代理透传原始 URL（凭据保留）。"""
    port = _http_proxy_server()
    sock = tunnel.connect_sync(f"http://u:p@127.0.0.1:{port}", "echo", 1234, timeout=5)
    assert _roundtrip(sock)
    sock.close()
