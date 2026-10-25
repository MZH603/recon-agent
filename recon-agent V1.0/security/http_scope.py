"""HTTP helpers that keep redirects within the requested host (scheme + hostname + port)."""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.response
import urllib.request


def _origin_tuple(url: str) -> tuple[str, str, int]:
    """Extract (scheme, hostname, port) from a URL or bare hostname."""
    # Accept bare hostname (e.g., "example.com") by defaulting to https://
    if "://" not in url:
        url = "https://" + url
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").rstrip(".").casefold()
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, hostname, port


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, str, int] | str) -> None:
        super().__init__()
        if isinstance(allowed_origin, str):
            allowed_origin = _origin_tuple(allowed_origin)
        self._allowed_origin = allowed_origin

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp,
        code: int,
        msg: str,
        headers,
        newurl: str,
    ) -> urllib.request.Request:
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        destination = _origin_tuple(resolved_url)
        if destination != self._allowed_origin:
            raise urllib.error.HTTPError(
                req.full_url, code, "Cross-origin redirect blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def urlopen_same_host(
    request: urllib.request.Request, *, timeout: float
) -> urllib.response.addinfourl:
    """Open a URL while rejecting redirects to any origin other than the request origin."""
    origin = _origin_tuple(request.full_url)
    if not origin[1]:
        raise ValueError("Request URL must include a host")
    opener = urllib.request.build_opener(_SameHostRedirectHandler(origin))
    return opener.open(request, timeout=timeout)
