"""指纹签名表（HARD：全部来自真实响应特征，禁止凭常识断言；来源强制标注）。"""
from __future__ import annotations

import re

# (header, value 正则, 类别, 名称, 置信度)
HEADER_SIGNATURES: tuple[tuple[str, str, str, str, float], ...] = (
    ("Server", r"nginx", "server", "Nginx", 0.9),
    ("Server", r"apache(?!-coyote)", "server", "Apache", 0.9),
    ("Server", r"microsoft-iis", "server", "IIS", 0.9),
    ("Server", r"tengine", "server", "OpenResty/Tengine", 0.9),
    ("Server", r"cloudflare", "cdn", "Cloudflare", 0.9),
    # ---- 中间件 ----
    ("Server", r"tomcat|coyote", "middleware", "Tomcat", 0.9),
    ("Server", r"weblogic", "middleware", "WebLogic", 0.9),
    ("Server", r"websphere", "middleware", "WebSphere", 0.9),
    ("Server", r"jetty", "middleware", "Jetty", 0.9),
    ("Server", r"jboss|wildfly", "middleware", "JBoss/WildFly", 0.9),
    ("Server", r"kestrel", "middleware", "Kestrel(.NET)", 0.9),
    ("Server", r"uvicorn", "middleware", "uvicorn(Python)", 0.9),
    ("Server", r"gunicorn", "middleware", "gunicorn(Python)", 0.9),
    ("Server", r"undertow", "middleware", "Undertow(Java)", 0.9),
    ("X-Powered-By", r"servlet|jsp", "middleware", "Tomcat/Servlet容器", 0.8),
    ("Set-Cookie", r"jsessionid", "middleware", "Java应用容器", 0.6),
    # ---- 语言 ----
    ("X-Powered-By", r"php/([\d\.]+)", "language", "PHP", 0.9),
    ("X-Powered-By", r"asp\.net", "framework", "ASP.NET", 0.9),
    ("X-Powered-By", r"express", "framework", "Express", 0.9),
    ("X-Powered-By", r"thinkphp", "framework", "ThinkPHP", 0.9),
    ("Set-Cookie", r"phpsessid", "language", "PHP", 0.7),
    ("Set-Cookie", r"jsessionid", "language", "Java", 0.7),
    ("Set-Cookie", r"asp\.net_sessionid", "language", "ASP.NET", 0.7),
    ("Set-Cookie", r"laravel_session", "framework", "Laravel", 0.8),
    ("Set-Cookie", r"csrftoken", "framework", "Django", 0.7),
    ("Set-Cookie", r"\bsessionid", "framework", "Django/Python", 0.5),  # \b 避免误报 JSESSIONID
    ("Set-Cookie", r"_rails|_session_id=", "framework", "Ruby on Rails", 0.6),
    ("Set-Cookie", r"flask|werkzeug", "framework", "Flask", 0.7),
    ("X-Application-Context", r".", "framework", "Spring Boot", 0.9),
    # ---- WAF/CDN ----
    ("Set-Cookie", r"cf_ray", "cdn", "Cloudflare", 0.8),
    ("cf-ray", r".", "cdn", "Cloudflare", 0.9),
    ("X-Sucuri-ID", r".", "waf", "Sucuri WAF", 0.9),
    ("X-WAF", r".", "waf", "WAF(未识别类型)", 0.5),
    ("Via", r"varnish", "server", "Varnish", 0.8),
    ("X-Redirect-By", r"wordpress", "cms", "WordPress", 0.95),
    ("X-Drupal-Cache", r".", "cms", "Drupal", 0.95),
    ("X-Generator", r"drupal", "cms", "Drupal", 0.9),
    ("X-AspNet-Version", r"([\d\.]+)", "framework", "ASP.NET", 0.9),
    ("X-Served-By", r"cache-", "cdn", "Fastly", 0.8),
    ("X-Amz-Cf-Id", r".", "cdn", "CloudFront", 0.85),
    ("X-GitHub-Request-Id", r".", "hosting", "GitHub Pages", 0.9),
    ("Server", r"openresty", "server", "OpenResty", 0.9),
    ("Server", r"caddy", "server", "Caddy", 0.9),
)

# (header, 版本捕获正则)：命中后为同名已知项补充 version 字段
VERSION_HEADER_SIGNATURES: tuple[tuple[str, str, str, str], ...] = (
    ("Server", r"nginx/([\d\.]+)", "server", "Nginx"),
    ("Server", r"apache/([\d\.]+)", "server", "Apache"),
    ("X-Powered-By", r"php/([\d\.]+)", "language", "PHP"),
)

# 页面特征 -> (类别, 名称, 置信度)
BODY_SIGNATURES: tuple[tuple[str, str, str, float], ...] = (
    (r"wp-content|wp-includes", "cms", "WordPress", 0.85),
    (r"/sites/default/files", "cms", "Drupal", 0.85),
    (r"Joomla!", "cms", "Joomla", 0.85),
    (r"typecho", "cms", "Typecho", 0.85),
    (r"powered by discuz|discuz!", "cms", "Discuz!", 0.85),
    (r"dedecms", "cms", "DedeCMS", 0.85),
    (r"empirecms|phome", "cms", "EmpireCMS", 0.75),
    (r"phpcms", "cms", "PHPCMS", 0.85),
    (r"metinfo", "cms", "MetInfo", 0.8),
    (r"ghost-url", "cms", "Ghost", 0.85),
    (r"hexo", "cms", "Hexo", 0.7),
    (r"thinkphp", "framework", "ThinkPHP", 0.7),
    (r"whitelabel error page", "framework", "Spring Boot", 0.85),
    (r"__NEXT_DATA__", "frontend", "Next.js", 0.85),
    (r"data-v-[0-9a-f]{8}", "frontend", "Vue", 0.7),
    (r"ng-version=", "frontend", "Angular", 0.85),
    (r"element-ui|element-plus", "frontend", "Element UI(Vue)", 0.8),
    (r"ant-design|antd", "frontend", "Ant Design(React)", 0.8),
    (r"layui", "frontend", "Layui", 0.8),
    (r"bootstrap", "frontend", "Bootstrap", 0.7),
    (r"jquery", "js库", "jQuery", 0.8),
    (r"webpack", "frontend", "Webpack", 0.6),
    # ---- 国内高校/政企常见系统与组件 ----
    (r"正方教务|zfsoft|zf_soft", "system", "正方教务系统", 0.9),
    (r"强智科技|强智教务|qzsoft", "system", "强智教务", 0.9),
    (r"青果教务|青果|qingguo", "system", "青果教务", 0.85),
    (r"超星|chaoxing|fanya\.chaoxing|学习通", "system", "超星学习通", 0.85),
    (r"雨课堂", "system", "雨课堂", 0.85),
    (r"webvpn|easyconn", "system", "深澜/WebVPN", 0.7),
    (r"致远oa|seeyon", "system", "致远OA", 0.9),
    (r"泛微|weaver|e-cology", "system", "泛微OA", 0.9),
    (r"蓝凌|landray", "system", "蓝凌OA", 0.9),
    (r"通达oa|tongda", "system", "通达OA", 0.85),
    (r"金和oa|jhsoft", "system", "金和OA", 0.85),
    (r"宝塔面板|bt\.cn|btpanel", "system", "宝塔面板", 0.85),
    (r"ueditor", "component", "UEditor", 0.8),
    (r"kindeditor", "component", "KindEditor", 0.8),
    (r"webuploader", "component", "WebUploader", 0.75),
    (r"echarts", "js库", "ECharts", 0.8),
    (r"swiper", "js库", "Swiper", 0.75),
    (r"layer\.(js|open)", "js库", "Layer", 0.75),
    (r"react-dom|data-reactroot", "frontend", "React", 0.8),
    (r"vue(\.min|\.runtime)?\.js", "frontend", "Vue", 0.85),
)

# 安全响应头存在性（L0 即可判定加固姿态；缺失项由 L2 沙箱探针确认）
SECURITY_HEADER_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("X-Frame-Options", "X-Frame-Options"),
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
)

# 页面 script 版本提取：(库名正则, 显示名)
SCRIPT_LIB_NAMES: dict[str, str] = {
    "jquery": "jQuery", "bootstrap": "Bootstrap", "layui": "Layui", "angular": "Angular",
    "vue": "Vue", "react": "React", "echarts": "ECharts", "swiper": "Swiper",
}
# script src 版本捕获需覆盖 vue/react 等运行时文件名
SCRIPT_VERSION_RE = re.compile(
    r"(jquery|bootstrap|layui|angular|vue|react|echarts|swiper)[\-\.]v?(\d+\.\d+(?:\.\d+)?)", re.I)
