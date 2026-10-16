# API 静态候选与浏览器观测

## 目标

区分静态源码中的 API 线索、浏览器实际发出的请求，以及服务端已验证的 API 行为。

## 工具选择

- 需要从同源页面或 JavaScript 提取线索时，经 `tool_catalog` 选择 `api_recon`，只处理授权目标内的同源 HTTP(S) 资源。
- 用户要求审阅已捕获的流量时，且 Caido 已配置启用，使用 `list_requests`、`view_request` 或 `list_sitemap`。
- 只有任务明确需要公开资料时，才用 `web_search` 或 `web_get_contents`；查询内容可能发往第三方服务。

## 结论边界

静态字符串、历史 URL、代理记录和外部搜索结果都不是 API 可用性或漏洞的证明。记录 URL、来源、状态码（若有）、截断和目标范围；不要尝试未授权的写入、认证绕过或破坏性请求。
