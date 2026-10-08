"""pytest 全局 fixture（HARD：测试禁止污染生产审计日志）。"""
import pytest

from utils.logger import configure_audit


@pytest.fixture(autouse=True)
def _isolate_model_environment(monkeypatch):
    """模型配置测试只使用显式测试变量，不继承操作者的连接或 Key。"""
    for name in ("RECON_MODEL", "RECON_API_BASE", "RECON_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_audit(tmp_path):
    """每个测试自动重定向审计文件到临时目录（HARD：生产 audit.log 只由真实作业写入）。"""
    configure_audit(tmp_path / "audit.log")
    yield
