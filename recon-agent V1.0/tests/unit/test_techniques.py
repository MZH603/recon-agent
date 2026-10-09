"""插件架构 + 签名扩容测试。"""
from tools.builtin.fingerprint import _apply_body
from tools.deep_fingerprint import DeepFingerprintParams
from tools.techniques import REGISTRY


def test_plugin_registry_discovery():
    names = {t.name for t in REGISTRY}
    assert {"error_page", "cms_paths", "favicon", "js_inventory"} <= names  # 插件自动注册


def test_error_page_plugin_matches_tomcat():
    plugin = next(t for t in REGISTRY if t.name == "error_page")
    findings = plugin.analyze({plugin.paths()[0]:
                               "<h1>HTTP Status 404</h1><p>Apache Tomcat/9.0.71</p>"})
    assert findings[0].name == "Tomcat" and findings[0].category == "middleware"


def test_cms_paths_plugin_matches_wordpress():
    plugin = next(t for t in REGISTRY if t.name == "cms_paths")
    findings = plugin.analyze({"/wp-login.php": "<link href='/wp-admin/css/login.min.css'>"})
    assert findings[0].name == "WordPress"


def test_favicon_plugin_computes_md5():
    plugin = next(t for t in REGISTRY if t.name == "favicon")
    findings = plugin.analyze({"/favicon.ico": "binary-ish"})
    assert findings[0].name == "favicon" and len(findings[0].version) == 32


def test_js_inventory_plugin_extracts_version():
    plugin = next(t for t in REGISTRY if t.name == "js_inventory")
    findings = plugin.analyze({"/": "<script src='/js/vue-3.4.21.min.js'></script>"})
    assert any(f.name == "Vue" and f.version == "3.4.21" for f in findings)


def test_fingerprint_detects_education_oa_and_editor():
    findings: dict = {}
    _apply_body("<title>正方教务管理系统</title><script src='ueditor.config.js'>", findings)
    assert findings["system"]["name"] == "正方教务系统"
    assert findings["component"]["name"] == "UEditor"
    oa: dict = {}
    _apply_body("<title>e-cology</title>", oa)
    assert oa["system"]["name"] == "泛微OA"


def test_deep_fingerprint_params_bounded():
    from tools.deep_fingerprint import PROBE_LIMIT
    assert PROBE_LIMIT == 8  # HARD: 单目标探测请求上限
    p = DeepFingerprintParams(target="example.com")
    assert p.include_baseline
