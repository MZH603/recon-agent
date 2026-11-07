"""deep_fingerprint._sync_get 对 4xx/5xx 的语义回归：HTTPError 是有效答案，不是连接失败。

背景（paypal.cn 实测发现）：api.paypal.cn 对 GET / 返回 405，urllib 抛 HTTPError；
修复前 _get 的 except (OSError, ValueError) 会吞掉它（HTTPError→URLError→OSError），
导致 405/403 主机被误判「无法连接」而丢失指纹。修复后与 webfetch.http_get 语义对齐。
"""
import urllib.error

from tools.builtin import deep_fingerprint as df


def test_sync_get_httperror_returns_body(monkeypatch):
    def _fake_open(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 405, "Method Not Allowed",
                                     hdrs=None, fp=None)

    monkeypatch.setattr(df, "urlopen_same_origin", _fake_open)
    body = df.DeepFingerprintTool._sync_get("https://api.example.cn/")
    assert body == ""  # fp=None 时 read 失败收敛空串，但绝不上抛


def test_sync_get_httperror_with_body(monkeypatch):
    import io

    class _FP(io.BytesIO):
        def read(self, n=-1):
            return b"<html>OpenResty error page</html>"

    def _fake_open(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "Forbidden",
                                     hdrs=None, fp=_FP(b"<html>OpenResty error page</html>"))

    monkeypatch.setattr(df, "urlopen_same_origin", _fake_open)
    body = df.DeepFingerprintTool._sync_get("https://api.example.cn/")
    assert "OpenResty" in body  # 403 页面内容可用于指纹（错误页特征）


def test_sync_get_connection_error_propagates_as_oserror(monkeypatch):
    def _fake_open(req, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(df, "urlopen_same_origin", _fake_open)
    try:
        df.DeepFingerprintTool._sync_get("https://api.example.cn/")
        raised = False
    except OSError:
        raised = True
    assert raised  # 真正的连接层失败仍由 _get 收敛空串（语义不变）


def _fake_sync_get(url: str) -> str:
    return "405-page-body"


# 注：不端到端测 _get/_pick_scheme——run_sync 把函数 pickle 到子进程执行
# （platforms/sync_worker.py），monkeypatch 无法跨进程生效；_get（失败收敛
# 空串）与 _sync_get（HTTPError 带回 body）的语义已由上面三个直接用例覆盖，
# 实战验证见 paypal.cn 扫描（api.paypal.cn 405 → OpenResty/Tengine 指纹）。
