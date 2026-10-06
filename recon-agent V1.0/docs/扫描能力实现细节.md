# recon-agent V1.0 扫描能力实现细节（L0/L1/L2 × 目标类型 × 实现手段）

> 本文档是扫描模式规范的技术实现附录，逐项列出每个扫描级别针对每种目标类型的
> 具体实现手段（协议/算法/数据源/字典/并发策略），以及代码文件引用。
> 所有实现均经过实弹验证（example.com / scanme.nmap.org / 自建靶场）。

---

## 全局不变量（所有级别共同遵守）

| 不变量 | 实现方式 | 代码 |
|---|---|---|
| 单线程限速 | `StealthRateLimiter`（Semaphore + 随机延迟） | security/stealth.py |
| 浏览器 UA | Chrome/Firefox/Safari 随机轮换，禁自定义扫描器 UA | security/stealth.py |
| 仅 TCP Connect | 禁 SYN/UDP/NULL/XMAS/FIN 等异常 packets | tools/builtin/port_scan.py |
| 失败即停 | ConnectionRefused=继续，Timeout=**立即停止该目标** | tools/builtin/port_scan.py |
| 403/401 答案 | HTTPError 作为有效指纹数据（WhatWeb 同款），非连接失败 | tools/builtin/webfetch.py |
| 审计哈希链 | 每条操作 prev+SHA256 链式防篡改 | utils/logger.py |
| 出站 scheme 白名单 | 全部 HTTP 出口统一走 webfetch.py（禁 file:///ftp://） | tools/builtin/webfetch.py |

---

## L0 · 被动测绘（零端口探测，纯公开数据源）

### 域名与子域名枚举

| 手段 | 实现细节 | 数据源 | 并发 |
|---|---|---|---|
| **证书透明度日志（CT）** | HTTP GET `crt.sh/?q=%25.{domain}&output=json` → 解析 JSON 提取 name 字段；降级链：crt.sh → certspotter API | crt.sh / certspotter | 串行（CT 链需递归依赖） |
| **被动 DNS（OTX）** | GET `otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns` → 解析 JSON passive_dns[].hostname | AlienVault OTX | `asyncio.gather` 并行 |
| **被动 DNS（RapidDNS）** | GET `rapiddns.io/subdomains/{domain}?full=1` → 正则提取 HTML 表格中的域名 | RapidDNS | `asyncio.gather` 并行 |
| **Host Search（HackerTarget）** | GET `api.hackertarget.com/hostsearch/?q={domain}` → 解析 CSV 格式（host,ip） | HackerTarget | `asyncio.gather` 并行 |
| **URL 扫描（urlscan）** | GET `urlscan.io/api/v1/search/?q=domain:{domain}&size=1000` → 解析 JSON results[].page.domain | urlscan.io | `asyncio.gather` 并行 |
| **TLS 证书 SAN** | Python `ssl.create_default_context()` 单次握手 → `getpeercert().get("subjectAltName")` | 目标 443 端口（单次握手） | 串行 |
| **DNS 字典验证** | 600 词内置字典（tools/data/subnames.txt）+ `socket.getaddrinfo(prefix.domain)` 并发验证（Semaphore(10)） | 系统解析器 | Semaphore(10) |
| **递归拓线** | 对发现的每个子域（≤10 个）再查一层 CT（`include_subdomains=true`） | crt.sh / certspotter | 同 CT |
| **存活解析** | `socket.getaddrinfo(host)` 逐主机验证 → 过滤不可达 | 系统解析器 | 串行 |

**代码**：tools/subdomain_enum.py · tools/builtin/passive_dns.py · collectors/asset_expander.py

### DNS 全记录

| 记录类型 | 实现 | 降级链 |
|---|---|---|
| A / AAAA / MX / NS / TXT / SOA / CNAME | DoH JSON API：`dns.google/resolve?name=&type=` → `dns.alidns.com/resolve?name=&type=`（`asyncio.gather` 5 类型并行） | 全部超时 → `socket.gethostbyname_ex` 兜底 |

**代码**：tools/builtin/dns_query.py

### WHOIS 注册信息

| 步骤 | 实现 |
|---|---|
| 第一步 | `socket.create_connection(("whois.iana.org", 43))` → 发送 `domain\r\n` → 解析 `refer:` 行获取注册商 |
| 第二步 | 连接 referral server（如 `whois.cnnic.cn:43`）→ 获取注册人/日期/NS |
| 特例 | `.edu.cn` 不在 CNNIC，归 CERNET（`whois.edu.cn`） |

**代码**：collectors/asset_expander.py::_whois_query

### IP / C 段

| 手段 | 实现 |
|---|---|
| IP 解析 | `socket.gethostbyname_ex(domain)` → 去重排序 |
| C 段 | `ip.rsplit(".", 1)[0] + ".0/24"` → **仅记录，永不扫描**（HARD） |

### Web 指纹（被动单次 GET）

| 手段 | 实现细节 | 签名数 |
|---|---|---|
| **Header 签名匹配** | 大小写不敏感查找 `Server` `X-Powered-By` `Set-Cookie` `X-Frame-Options` 等 14 种 Header，匹配 40+ 签名（正则） | 40+ |
| **meta generator** | `<meta name="generator" content="...">` 正则提取 → 名称+版本 | — |
| **页面 body 特征** | 路径/CSS 类名/DOM 属性匹配（`wp-content` → WordPress、`data-v-` → Vue、`ng-version` → Angular 等） | 22 |
| **版本精确提取** | `SCRIPT_VERSION_RE` 从 `<script src>` 提取精确版本（如 jquery-3.6.0 → jQuery 3.6.0） | 8 种 JS 库 |
| **安全头存在性** | X-Frame-Options / HSTS / CSP / X-Content-Type-Options 存在性检测 | 4 |
| **Server 版本提取** | `nginx/1.24.0`、`Apache/2.4.x` 等格式正则 | 3 |
| **降级链** | https 失败 → http 兜底一次；证书不匹配（IP 目标）→ CERT_NONE 重试一次 | — |

**签名表**：tools/builtin/signatures.py（HEADER_SIGNATURES + BODY_SIGNATURES + VERSION_HEADER_SIGNATURES + SECURITY_HEADER_SIGNATURES + SCRIPT_LIB_NAMES）
**代码**：tools/builtin/fingerprint.py

### 探活（httpx_probe）

| 手段 | 实现 |
|---|---|
| httpx CLI | `httpx -u {url} -silent -status-code -title -tech-detect -no-color` |
| 降级 | httpx 缺失 → builtin 指纹工具（单次 GET） |

**代码**：tools/httpx_tool.py

### 历史端点（Wayback）

| 手段 | 实现 |
|---|---|
| CDX API | GET `web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&filter=statuscode:200` → 提取路径 |

**代码**：tools/wayback_urls.py

### 子域接管候选

| 手段 | 实现 |
|---|---|
| CNAME 查询 | DoH `dns_query(target, rtype=CNAME)` |
| 悬空检测 | CNAME 指向第三方托管（GitHub Pages / S3 / Azure / Netlify / Vercel 等 11 家签名）+ 响应体"未部署"特征匹配 |
| 判定 | CNAME → 第三方托管 + 特征页匹配 = **接管候选（High）** |

**代码**：tools/takeover_check.py

---

## L1 · 隐蔽端口扫描

### 端口探测

| 手段 | 实现细节 |
|---|---|
| **扫描方法** | `asyncio.open_connection(host, port)` + `wait_for(timeout=10s)` —— 纯 TCP Connect，无 SYN/UDP |
| **端口集** | 11 端口：80, 443, 22, 8080, 8443, 3389, 3306, 5432, 6379, 9929, 31337 |
| **端口上限** | ≤20/次（HARD） |
| **限速** | 每次连接前 `asyncio.sleep(random.uniform(3, 10))` —— 模拟人类节奏 |
| **失败即停** | ConnectionRefused → `closed` 列表（继续）；Timeout/OSError → **立即停止该目标**，不重试 |
| **结果分类** | `open_ports`（成功连接）/ `closed`（refused）/ `stopped_early`（超时终止标记） |
| **降级链** | nmap → builtin socket（nmap_scan 自动降级到 BuiltinPortScan，跨 Schema 参数转换） |

**代码**：tools/nmap_tool.py（编排+降级）· tools/builtin/port_scan.py（socket 实现）

### 降级链

```
nmap CLI 可用？
  ├── 是 → nmap -sT --max-rate 1 --max-parallelism 1 -p {ports} {target}
  │        enforce_stealth() 强制注入安全参数 + 剔除禁用参数
  └── 否 → BuiltinPortScan（asyncio socket 逐端口 Connect）
           [降级模式] 标注 + 置信度 0.9→0.6
```

---

## L2 · 深度探测

### 深度指纹（WhatWeb 式插件化引擎）

| 插件 | 探测路径 | 分析方法 | 发现 |
|---|---|---|---|
| **error_page** | `/{random}`（随机不存在路径） | 默认 404 页特征匹配：Tomcat / Spring Boot whitelabel / IIS / Nginx / WebLogic / WebSphere | middleware / framework / server |
| **cms_paths** | `/wp-login.php` `/wp-json/` `/administrator/` `/user/login` | 登录面特征匹配：wp-content / namespaces / joomla / drupal | cms |
| **favicon** | `/favicon.ico` | SHA256(md5) → 跨主机同值 = 同源部署（聚类情报） | 情报 |
| **js_inventory** | `/`（首页） | `<script src>` 正则提取库名+精确版本（jQuery 3.6.0 / Vue 3.4.21 等 8 种） | js库 |

**引擎**：tools/deep_fingerprint.py（≤10 GET/台，`asyncio.gather` 限速分发）
**插件**：tools/techniques/（base.py + 4 个插件 + @register 装饰器注册表）

### 敏感路径枚举 + 泄露嗅探

| 手段 | 实现细节 |
|---|---|
| **内置字典** | 75 条按价值排序的敏感路径（.env / .git / 备份 / phpinfo / actuator / CMS 登录面…），合并后受 `max_paths` ≤80 截断 |
| **CMS 感知路径生成** | 指纹阶段识别的 CMS 类型 → 自动注入该 CMS 特有路径（Drupal 13 条 / WordPress 6 条 / Joomla 4 条） |
| **robots.txt 解析** | 200 → 逐行提取 `Disallow:` 路径 → 作为额外情报（不自动探测，仅记录） |
| **状态码分类** | 200=可访问 / 401=存在需认证 / 403=存在禁止 / 404=跳过 |
| **内容泄露嗅探** | 200 响应体 → `sniff_leaks()` 匹配 17 类泄露签名（私钥/AWS Key/连接串/Git 元数据/JWT/目录列表/phpinfo/堆栈泄露…） |
| **严重度分级** | High=确认敏感数据暴露（私钥/密钥/连接串）→ Medium=存在需认证 → Info=可访问未见泄露 |
| **证据绑定** | 每条发现附响应体 SHA256 前 64 字节哈希 |
| **失败即停** | 连接层失败（-1 哨兵）→ 立即停止该目标 |

**代码**：tools/dir_enum.py · tools/builtin/leak_signatures.py

### CMS 感知路径生成

| 已识别 CMS | 自动注入的特有路径 |
|---|---|
| Drupal | `/user/login` `/user/reset/1` `/cron.php` `/xmlrpc.php` `/install.php` `/update.php` `/admin/config` `/admin/people` `/node/1` `/node/2` `/sites/default/files/` `/profiles/standard/` `/CHANGELOG.txt` `/README.txt` `/MAINTAINERS.txt` |
| WordPress | `/wp-json/wp/v2/users` `/wp-json/` `/wp-content/debug.log` `/xmlrpc.php` `/wp-includes/version.php` `/readme.html` |
| Joomla | `/administrator/manifests/files/joomla.xml` `/language/en-GB/en-GB.xml` `/components/com_users/` `/images/` |

### 沙箱探针（script_probe）

| 手段 | 实现 |
|---|---|
| 探测脚本 | 用户/LLM 编写的 Python 脚本（如安全响应头读取器） |
| 三层沙箱 | AST 黑名单（禁 os/subprocess/eval/open）→ Bandit 扫描（HIGH 级发现拒绝）→ 运行时隔离（Docker 或宿主机+超时） |
| 目标注入 | `__TARGET__` 占位符由编排脚本替换为实际目标 |

---

## 信息采集覆盖矩阵（目标类型 × L0/L1/L2）

| 目标类型 | L0 被动测绘 | L1 端口扫描 | L2 深度探测 |
|---|---|---|---|
| **域名（A 记录）** | ✅ DoH 5 类型 + CT 子域 + SAN + 字典 + Wayback + 接管 | ✅ TCP Connect 11 端口 | ✅ 深度指纹 + 路径枚举 + 泄露嗅探 |
| **IP（公网）** | ✅ 指纹（证书跳过 + 403 答案） | ✅ TCP Connect | ✅ 深度指纹 + 路径枚举 |
| **IP（内网 --lab）** | ✅ 同上 | ✅ 同上 | ✅ 同上 |
| **host:port（非标端口）** | ✅ 指纹（split_target 解析端口） | — | — |
| **URL（带 scheme）** | ✅ 指纹（urlsplit 解析） | — | — |
| **IPv6（裸/括号）** | ✅ 解析 + 合规校验 | — | — |
| **不可解析域名** | ✅ 优雅失败（显式记录） | — | — |
| **子域名** | ✅ subdomain_enum 8 源 | ✅ dir_enum（范围内） | ✅ dir_enum + deep_fingerprint |

---

## Token 降损与效率优化（全链路）

| 手段 | 实现位置 | 效果 |
|---|---|---|
| **ContextTrimmer** | efficiency/context_trimmer.py → core/context.py | 超预算裁剪旧消息，保留 system 前缀（Prompt Cache 命中） |
| **TemplateCompressor** | efficiency/template_compressor.py → core/context.py | nmap/httpx 固定格式输出 → 仅注入变量部分 |
| **CallDeduplicator** | efficiency/deduplicator.py → core/agent.py | hash(目标+工具+参数) 命中缓存直接复用 |
| **BudgetGuard** | efficiency/budget_guard.py → core/llm.py | 60% 停 L2 / 80% 只被动 / 100% 断 LLM + [INCOMPLETE] 水印 |
| **IncrementalReporter** | efficiency/incremental.py | 同目标同工具结果无变化 → 标 unchanged 跳过 |
| **大输出落盘** | core/context.py::_dump_raw | >1500 token 工具结果落盘，上下文只留指针 |
| **DoH 解析器记忆** | tools/builtin/dns_query.py | 首次超时后发现可用源 → 后续直连（22s→2s） |
| **并发 DNS 类型** | collectors/asset_expander.py | 5 类型 `asyncio.gather` 并行（55s→25s） |
| **并发被动源** | tools/subdomain_enum.py | 4 源 `asyncio.gather` 并行（20s→10.6s） |
| **并发指纹** | collectors/web_fingerprint.py | `Semaphore(3)` 跨主机并行（63s→21s） |

---

## 未实现 / 规划中的能力

| 能力 | 说明 | 优先级 |
|---|---|---|
| **HTML 链接提取爬虫** | 解析首页 `<a href>` 发现内部页面 → 递归爬取（深度≤1） | v1.1 |
| **JS bundle 端点提取** | 解析 JS 文件中的 API 路径/路由 → 发现隐藏接口 | v1.1 |
| **子域置换生成** | 已知子域 + 常见前缀组合（如 `dev-{sub}` `{sub}-test`）| v1.1 |
| **Wappalyzer 式大规模签名库** | 3000+ 签名 JSON + 浏览器端 DOM 分析 | v2.0 |
| **favicon 哈希库** | 收集常见 CMS 的 favicon md5 → 反查 CMS 类型 | v1.1 |
| **Nmap 版本扫描（-sV）** | 需要放宽当前禁止 `-sV` 的 HARD 约束 | 待讨论 |
| **SSE 模式 MCP** | Server-Sent Events 替代 stdio（支持远程 Agent 接入） | v2.0 |
