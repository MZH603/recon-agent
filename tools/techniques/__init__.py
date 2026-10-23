"""WhatWeb 式探测插件包：导入子模块完成注册，引擎经 REGISTRY 分发。

插件列表：
- error_page    错误页中间件指纹（404 页特征匹配）
- cms_paths     CMS 登录面/REST 端点探测
- favicon       favicon md5 跨主机关联
- js_inventory  首页 JS 库版本提取
- html_crawler  HTML 结构分析（链接/表单/注释/邮箱）
- js_endpoints  JS 端点与凭据提取（两阶段：发现 JS → 抓取分析）
"""
from tools.techniques.base import REGISTRY, Finding, Technique, register  # noqa: F401
from tools.techniques import (  # noqa: F401
    cms_paths, error_page, favicon, html_crawler, js_endpoints, js_inventory,
)
