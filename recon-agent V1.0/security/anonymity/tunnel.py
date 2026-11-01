"""隧道原语（HARD：零第三方依赖，纯手写 HTTP CONNECT / SOCKS5 握手）。

安全语义：
- SOCKS5 一律 ATYP=domain 远端解析（反 DNS 溯源：本地不产生针对目标的 DNS 查询）；
- HTTP(S) 代理 CONNECT 隧道建立后仍由本端做 TLS（证书按原 hostname 校验，端到端加密）；
- 握手响应异常（非 200 / 非 SOCKS5 成功码）一律显式失败，不降级直连。
"""
from __future__ import annotations

import asyncio
import base64
import socket
import struct
import urllib.parse
import urllib.request

from security.anonymity.config import TOR_CONTROL_TIMEOUT_SECONDS, TOR_DEFAULT_CONTROL_PORT

_SOCKS5_VERSION = 0x05
_SOCKS5_AUTH_NONE = 0x00
_SOCKS5_AUTH_USERPASS = 0x02
_SOCKS5_CMD_CONNECT = 0x01
_SOCKS5_ATYP_IPV4 = 0x01
_SOCKS5_ATYP_DOMAIN = 0x03
_SOCKS5_ATYP_IPV6 = 0x04
_SOCKS5_REPLY_OK = 0x00
_TUNNEL_READ_SIZE = 1024


class TunnelError(Exception):
    """代理隧道建立失败（HARD：调用方必须 fail closed，禁止降级直连）。"""


def _proxy_parts(proxy_url: str) -> tuple[str, str, int, str | None, str | None]:
    """拆 (scheme, host, port, user, password)。"""
    parsed = urllib.parse.urlsplit(proxy_url)
    if not parsed.hostname:
        raise TunnelError(f"代理 URL 缺少主机: {proxy_url[:80]}")
    scheme = parsed.scheme.lower()
    if scheme == "socks5h":
        scheme = "socks5"
    if scheme not in ("http", "https", "socks5"):
        raise TunnelError(f"不支持的代理 scheme: {scheme}")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else (9050 if scheme == "socks5" else 80)
    return scheme, parsed.hostname, port, parsed.username, parsed.password


def _socks5_greeting_sync(sock: socket.socket, user: str | None, password: str | None) -> None:
    methods = [bytes([_SOCKS5_AUTH_NONE])]
    if user is not None:
        methods.insert(0, bytes([_SOCKS5_AUTH_USERPASS]))
    sock.sendall(bytes([_SOCKS5_VERSION, len(methods)]) + b"".join(methods))
    resp = sock.recv(2)
    if len(resp) < 2 or resp[0] != _SOCKS5_VERSION:
        raise TunnelError("SOCKS5 问候响应异常")
    if resp[1] == 0xFF:
        raise TunnelError("SOCKS5 代理不接受可用认证方式")
    if resp[1] == _SOCKS5_AUTH_USERPASS:
        u = (user or "").encode("utf-8")
        p = (password or "").encode("utf-8")
        sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        auth = sock.recv(2)
        if len(auth) < 2 or auth[1] != _SOCKS5_REPLY_OK:
            raise TunnelError("SOCKS5 用户名/密码认证失败")


def _socks5_request_sync(sock: socket.socket, host: str, port: int) -> None:
    host_bytes = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode("ascii")
    if len(host_bytes) > 255:
        raise TunnelError("SOCKS5 目标主机名超长")
    # HARD: 一律 ATYP=domain 交由代理端解析（含数字地址以外的所有目标）
    req = struct.pack("!BBBBBH", _SOCKS5_VERSION, _SOCKS5_CMD_CONNECT, 0x00,
                      _SOCKS5_ATYP_DOMAIN, len(host_bytes), port) + host_bytes
    sock.sendall(req)
    head = _recv_exact_sync(sock, 4)
    if head[1] != _SOCKS5_REPLY_OK:
        raise TunnelError(f"SOCKS5 CONNECT 失败: reply={head[1]}")
    atyp = head[3]
    if atyp == _SOCKS5_ATYP_IPV4:
        _recv_exact_sync(sock, 4 + 2)
    elif atyp == _SOCKS5_ATYP_DOMAIN:
        dlen = _recv_exact_sync(sock, 1)[0]
        _recv_exact_sync(sock, dlen + 2)
    elif atyp == _SOCKS5_ATYP_IPV6:
        _recv_exact_sync(sock, 16 + 2)
    else:
        raise TunnelError(f"SOCKS5 未知 ATYP: {atyp}")


def _recv_exact_sync(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise TunnelError("SOCKS5 响应提前结束")
        buf += chunk
    return buf


def socks5_connect_sync(proxy_url: str, host: str, port: int, timeout: float) -> socket.socket:
    """同步 SOCKS5 CONNECT：返回已建立隧道的原始 socket（TLS 由调用方接管）。"""
    scheme, proxy_host, proxy_port, user, password = _proxy_parts(proxy_url)
    if scheme != "socks5":
        raise TunnelError("socks5_connect_sync 仅接受 socks5:// 代理")
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        _socks5_greeting_sync(sock, user, password)
        _socks5_request_sync(sock, host, port)
    except (OSError, TunnelError):
        sock.close()
        raise
    sock.settimeout(timeout)
    return sock


def http_connect_sync(proxy_url: str, host: str, port: int, timeout: float) -> socket.socket:
    """同步 HTTP CONNECT 隧道：返回已建立隧道的原始 socket（TLS 由调用方接管）。"""
    scheme, proxy_host, proxy_port, user, password = _proxy_parts(proxy_url)
    if scheme != "http":
        raise TunnelError("http_connect_sync 仅接受 http:// 代理")
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
        req = f"CONNECT {authority}:{port} HTTP/1.1\r\nHost: {authority}:{port}\r\n"
        if user is not None:
            token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
            req += f"Proxy-Authorization: Basic {token}\r\n"
        req += "\r\n"
        sock.sendall(req.encode("ascii"))
        status_line = b""
        while b"\r\n" not in status_line:
            chunk = sock.recv(_TUNNEL_READ_SIZE)
            if not chunk:
                raise TunnelError("CONNECT 响应提前结束")
            status_line += chunk
            if len(status_line) > 8192:
                raise TunnelError("CONNECT 响应超长")
        code = status_line.split(b" ", 2)[1] if b" " in status_line else b""
        if code != b"200":
            raise TunnelError(f"CONNECT 被拒绝: HTTP {code.decode('ascii', 'replace')}")
    except (OSError, TunnelError):
        sock.close()
        raise
    sock.settimeout(timeout)
    return sock


def connect_sync(proxy_url: str, host: str, port: int, timeout: float) -> socket.socket:
    """按 scheme 自动选择同步隧道。https:// 代理以 TLS 包裹 CONNECT（本端先握手 TLS）。

    HARD：代理凭据（user:pass@）原样保留，不得在 scheme 改写时丢失。
    """
    scheme, proxy_host, proxy_port, user, password = _proxy_parts(proxy_url)
    if scheme == "socks5":
        return socks5_connect_sync(proxy_url, host, port, timeout)
    if scheme == "https":
        # 先与本端 TLS 握手（保留代理认证），再经加密通道发 CONNECT
        sock = _plain_connect(proxy_host, proxy_port, timeout)
        import ssl as _ssl
        context = _ssl.create_default_context()
        try:
            tls_sock = context.wrap_socket(sock, server_hostname=proxy_host)
        except (OSError, _ssl.SSLError):
            sock.close()
            raise TunnelError(f"到 HTTPS 代理 {proxy_host}:{proxy_port} 的 TLS 握手失败")
        try:
            _http_connect_over(tls_sock, proxy_host, proxy_port, host, port, user, password)
        except (OSError, TunnelError):
            tls_sock.close()
            raise
        return tls_sock
    return http_connect_sync(proxy_url, host, port, timeout)


def _plain_connect(proxy_host: str, proxy_port: int, timeout: float) -> socket.socket:
    """裸 TCP 连接代理（不带 scheme 改写）。"""
    return socket.create_connection((proxy_host, proxy_port), timeout=timeout)


def _http_connect_over(sock: socket.socket, proxy_host: str, proxy_port: int,
                       host: str, port: int, user: str | None, password: str | None) -> None:
    """在已连接（可选已 TLS）的代理 socket 上完成 HTTP CONNECT 握手。"""
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    req = f"CONNECT {authority}:{port} HTTP/1.1\r\nHost: {authority}:{port}\r\n"
    if user is not None:
        token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
        req += f"Proxy-Authorization: Basic {token}\r\n"
    req += "\r\n"
    sock.sendall(req.encode("ascii"))
    status_line = b""
    while b"\r\n" not in status_line:
        chunk = sock.recv(_TUNNEL_READ_SIZE)
        if not chunk:
            raise TunnelError("CONNECT 响应提前结束")
        status_line += chunk
        if len(status_line) > 8192:
            raise TunnelError("CONNECT 响应超长")
    code = status_line.split(b" ", 2)[1] if b" " in status_line else b""
    if code != b"200":
        raise TunnelError(f"CONNECT 被拒绝: HTTP {code.decode('ascii', 'replace')}")


def wrap_tls(sock: socket.socket, server_hostname: str, insecure: bool = False) -> socket.socket:
    """对隧道 socket 做 TLS 包裹（证书按原目标 hostname 校验）。"""
    import ssl as _ssl
    context = _ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = _ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=server_hostname)


# ---------------- asyncio 变体（integration_http 使用） ----------------

async def _socks5_greeting_async(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                 user: str | None, password: str | None) -> None:
    methods = [bytes([_SOCKS5_AUTH_NONE])]
    if user is not None:
        methods.insert(0, bytes([_SOCKS5_AUTH_USERPASS]))
    writer.write(bytes([_SOCKS5_VERSION, len(methods)]) + b"".join(methods))
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp[0] != _SOCKS5_VERSION:
        raise TunnelError("SOCKS5 问候响应异常")
    if resp[1] == 0xFF:
        raise TunnelError("SOCKS5 代理不接受可用认证方式")
    if resp[1] == _SOCKS5_AUTH_USERPASS:
        u = (user or "").encode("utf-8")
        p = (password or "").encode("utf-8")
        writer.write(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        await writer.drain()
        auth = await reader.readexactly(2)
        if auth[1] != _SOCKS5_REPLY_OK:
            raise TunnelError("SOCKS5 用户名/密码认证失败")


async def _socks5_request_async(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                host: str, port: int) -> None:
    host_bytes = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode("ascii")
    if len(host_bytes) > 255:
        raise TunnelError("SOCKS5 目标主机名超长")
    writer.write(struct.pack("!BBBBBH", _SOCKS5_VERSION, _SOCKS5_CMD_CONNECT, 0x00,
                             _SOCKS5_ATYP_DOMAIN, len(host_bytes), port) + host_bytes)
    await writer.drain()
    head = await reader.readexactly(4)
    if head[1] != _SOCKS5_REPLY_OK:
        raise TunnelError(f"SOCKS5 CONNECT 失败: reply={head[1]}")
    atyp = head[3]
    if atyp == _SOCKS5_ATYP_IPV4:
        await reader.readexactly(6)
    elif atyp == _SOCKS5_ATYP_DOMAIN:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atyp == _SOCKS5_ATYP_IPV6:
        await reader.readexactly(18)
    else:
        raise TunnelError(f"SOCKS5 未知 ATYP: {atyp}")


async def socks5_connect_async(proxy_url: str, host: str, port: int, timeout: float):
    """异步 SOCKS5 CONNECT：返回 (reader, writer)。"""
    scheme, proxy_host, proxy_port, user, password = _proxy_parts(proxy_url)
    if scheme != "socks5":
        raise TunnelError("socks5_connect_async 仅接受 socks5:// 代理")
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        await _socks5_greeting_async(reader, writer, user, password)
        await _socks5_request_async(reader, writer, host, port)
    except (OSError, asyncio.IncompleteReadError, TunnelError):
        writer.close()
        raise
    return reader, writer


async def http_connect_async(proxy_url: str, host: str, port: int, timeout: float):
    """异步 HTTP CONNECT 隧道：返回 (reader, writer)。"""
    scheme, proxy_host, proxy_port, user, password = _proxy_parts(proxy_url)
    if scheme != "http":
        raise TunnelError("http_connect_async 仅接受 http:// 代理")
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    try:
        authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
        req = f"CONNECT {authority}:{port} HTTP/1.1\r\nHost: {authority}:{port}\r\n"
        if user is not None:
            token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
            req += f"Proxy-Authorization: Basic {token}\r\n"
        req += "\r\n"
        writer.write(req.encode("ascii"))
        await writer.drain()
        status_line = await reader.readline()
        code = status_line.split(b" ", 2)[1] if b" " in status_line else b""
        if code != b"200":
            raise TunnelError(f"CONNECT 被拒绝: HTTP {code.decode('ascii', 'replace')}")
        while True:  # 吃掉 CONNECT 响应剩余头
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
    except (OSError, TunnelError):
        writer.close()
        raise
    return reader, writer


async def connect_async(proxy_url: str, host: str, port: int, timeout: float, insecure: bool = False):
    """按 scheme 自动选择异步隧道；https:// 代理先与本端 TLS 握手再 CONNECT（保留代理认证）。"""
    scheme, proxy_host, proxy_port, user, password = _proxy_parts(proxy_url)
    if scheme == "socks5":
        return await socks5_connect_async(proxy_url, host, port, timeout)
    if scheme == "https":
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        import ssl as _ssl
        context = _ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = _ssl.CERT_NONE
        try:
            await writer.start_tls(context, server_hostname=proxy_host)
            await _http_connect_over_async(writer, reader, host, port, user, password)
        except (OSError, _ssl.SSLError, asyncio.IncompleteReadError, TunnelError):
            writer.close()
            raise
        return reader, writer
    return await http_connect_async(proxy_url, host, port, timeout)


async def _http_connect_over_async(writer: asyncio.StreamWriter, reader: asyncio.StreamReader,
                                   host: str, port: int, user: str | None, password: str | None) -> None:
    """在已连接（可选已 TLS）的异步代理流上完成 HTTP CONNECT 握手。"""
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    req = f"CONNECT {authority}:{port} HTTP/1.1\r\nHost: {authority}:{port}\r\n"
    if user is not None:
        token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
        req += f"Proxy-Authorization: Basic {token}\r\n"
    req += "\r\n"
    writer.write(req.encode("ascii"))
    await writer.drain()
    status_line = await reader.readline()
    code = status_line.split(b" ", 2)[1] if b" " in status_line else b""
    if code != b"200":
        raise TunnelError(f"CONNECT 被拒绝: HTTP {code.decode('ascii', 'replace')}")
    while True:  # 吃掉 CONNECT 响应剩余头
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break


def tor_newnym(control_host: str = "127.0.0.1", control_port: int = TOR_DEFAULT_CONTROL_PORT,
               password: str = "", timeout: float = TOR_CONTROL_TIMEOUT_SECONDS) -> bool:
    """请求 Tor 控制端口 SIGNAL NEWNYM 换出口电路（独立于数据面的最小控制实现）。

    认证顺序：配置密码优先；无密码时尝试 SAFECOOKIE 认证（Tor 默认）。
    返回 True=已请求换路；False=控制面不可用（数据面照常工作，仅记录审计）。
    """
    try:
        sock = socket.create_connection((control_host, control_port), timeout=timeout)
    except OSError:
        return False
    try:
        f = sock.makefile("rwb")
        try:
            if password:
                f.write(f'AUTHENTICATE "{password}"\r\n'.encode("ascii"))
            else:
                challenge = _tor_authenticate_safecookie(f)
                if challenge is None:
                    return False
            f.flush()
            auth_resp = f.readline().decode("ascii", "replace").strip()
            if not auth_resp.startswith("250"):
                return False
            f.write(b"SIGNAL NEWNYM\r\n")
            f.flush()
            signal_resp = f.readline().decode("ascii", "replace").strip()
            return signal_resp.startswith("250")
        finally:
            try:
                f.close()
            except OSError:
                pass
    except OSError:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _tor_authenticate_safecookie(f) -> bytes | None:
    """SAFECOOKIE 双向认证握手（Tor CookieAuth 默认协议）；失败返回 None。"""
    import hashlib
    import os as _os

    from pathlib import Path
    cookie_path = _tor_cookie_path()
    if cookie_path is None:
        return None
    client_nonce = _os.urandom(32)
    f.write(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}\r\n".encode("ascii"))
    f.flush()
    resp = f.readline().decode("ascii", "replace").strip()
    if not resp.startswith("250 AUTHCHALLENGE"):
        return None
    try:
        server_nonce = bytes.fromhex(resp.split("ServerNonce=")[1].split(" ")[0])
        server_hash = resp.split("ServerHash=")[1].split(" ")[0]
        cookie = Path(cookie_path).read_bytes()
    except (IndexError, ValueError, OSError):
        return None
    prefix = b"Tor safe cookie authentication server-to-controller "
    expected = hashlib.sha256(prefix + client_nonce + server_nonce + cookie).hexdigest()
    if server_hash != expected:
        return None
    prefix_c = b"Tor safe cookie authentication controller-to-server "
    client_hash = hashlib.sha256(prefix_c + client_nonce + server_nonce + cookie).hexdigest()
    f.write(f"AUTHENTICATE {client_hash}\r\n".encode("ascii"))
    return client_hash


def _tor_cookie_path():
    """Tor 控制 cookie 的常见路径（存在才返回）；Windows 交由密码认证。"""
    import os as _os
    from pathlib import Path
    if _os.name == "nt":
        return None
    for candidate in ("/run/tor/control.authcookie", "/var/run/tor/control.authcookie",
                      _os.path.expanduser("~/.tor/control.authcookie")):
        if _os.path.exists(candidate):
            return Path(candidate)
    return None


def socks5_socket_for_urllib(proxy_url: str, timeout: float):
    """为 urllib 自定义 Handler 提供「由代理建连」的 socket 工厂。"""
    def factory(host: str, port: int) -> socket.socket:
        return socks5_connect_sync(proxy_url, host, port, timeout)
    return factory
