import email.message
import urllib.error
import urllib.request

import pytest

from security.http_scope import _SameHostRedirectHandler


def test_same_host_redirect_is_allowed():
    handler = _SameHostRedirectHandler("example.com")
    request = urllib.request.Request("https://example.com/start")

    redirected = handler.redirect_request(
        request, None, 302, "Found", email.message.Message(), "/next"
    )

    assert redirected.full_url == "https://example.com/next"


@pytest.mark.parametrize(
    "location",
    [
        "https://attacker.example/collect",
        "https://sub.example.com/next",
        "//attacker.example/collect",
    ],
)
def test_cross_host_redirect_is_rejected(location):
    handler = _SameHostRedirectHandler("example.com")
    request = urllib.request.Request("https://example.com/start")

    with pytest.raises(urllib.error.HTTPError, match="Cross-host redirect blocked"):
        handler.redirect_request(
            request, None, 302, "Found", email.message.Message(), location
        )
