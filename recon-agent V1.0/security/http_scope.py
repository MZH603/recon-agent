"""HTTP helpers that keep redirects within the requested host."""
from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.response
import urllib.request


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_host: str) -> None:
        super().__init__()
        self._allowed_host = allowed_host.rstrip(".").casefold()

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
        destination = urllib.parse.urlsplit(resolved_url).hostname
        if destination is None or destination.rstrip(".").casefold() != self._allowed_host:
            raise urllib.error.HTTPError(
                req.full_url, code, "Cross-host redirect blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


def urlopen_same_host(
    request: urllib.request.Request, *, timeout: float
) -> urllib.response.addinfourl:
    """Open a URL while rejecting redirects to any host other than the request host."""
    host = urllib.parse.urlsplit(request.full_url).hostname
    if not host:
        raise ValueError("Request URL must include a host")
    opener = urllib.request.build_opener(_SameHostRedirectHandler(host))
    return opener.open(request, timeout=timeout)
