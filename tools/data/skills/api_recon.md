# API 线索与请求观测

api_recon 静态解析页面和 JS；字符串、前端路由与 mock 均是候选。方法未知就保持未知，不根据路径猜测访问成功。

浏览器流程：tool_catalog 披露 mcp_tools/mcp_call，发现已配置 browser 服务，按授权导航、读取 browser_network_requests；将本地 evidence_id 传给 api_recon.runtime_evidence_ids。Caido list_requests 的本地证据也可按 ID 导入。

真实请求记录证明发生过该请求，不能证明当前仍可访问、接口无鉴权或存在漏洞。结果保留 method、path、参数名称、来源及 observed 状态。不要把 Cookie 或认证信息写进摘要。
