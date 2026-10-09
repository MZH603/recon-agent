# 扩展工具接入

本项目提供受控扫描器、搜索、代理只读查询、按需知识加载和工作记录，使用原生 `BaseTool` / `ToolResult` 接口。工具经过目标范围、合规、L1/L2 门控、执行日志和证据保存。通用 Shell、多 Agent 调度和整套外部 Agent 运行时不在接入范围。

## 已实现能力

| 工具 | 最低级别 | 用途 |
|---|---|---|
| subfinder_enum | L0 | 从固定 hackertarget 被动来源补充子域候选，标注枚举不完整 |
| katana_crawl | L2 | 单主机有界爬取，禁止重定向，最多 80 页 |
| ffuf_enum | L2 | 只检查模型提供的最多 80 个明确相对路径，禁重定向 |
| naabu_scan | L2 | 最多 20 个明确 TCP Connect 端口，逐端口单次探测 |
| nuclei_scan | L2 | 操作者指定本地简单 GET/HEAD 模板，命中仍是候选 |
| web_search | L0 | Exa 或 Perplexity 第三方情报，保留来源与未验证标记 |
| web_get_contents | L0 | 通过 Exa 读取最多 5 个公开资料 URL |
| list_requests / view_request / list_sitemap | L0 | Caido 元数据只读查询，过滤当前调用目标，省略查询值、请求头和正文 |
| skill_catalog / load_skill | L0 | 从安装包按名称加载少量 Recon 参考资料 |
| recon_note / recon_coverage / recon_threat_model / recon_finding | L0 | 按目标和会话保存记录，支持创建、查询、修订和删除 |
| workspace_snapshot | L0 | 读取当前记录快照，供报告使用 |

nmap、httpx、API 静态采集和浏览器 MCP 复用现有实现，不引入额外的 Agent SDK、Docker 沙箱或浏览器运行时。

## 启用与依赖

在 `recon-agent V1.0` 目录执行：

```powershell
Copy-Item tools/data/tool-integrations.example.yaml tools.local.yaml
python -m cli.main --tools-config tools.local.yaml --list-tools
python -m cli.main --session -t example.com --authorized --tools-config tools.local.yaml
```

编辑 `tools.local.yaml`，填入本机真实程序路径，启用需要的条目。裸启动/`--auth` 的扩展工具列表也支持勾选这些条目。选择只影响本次会话，不安装工具或执行请求。

CLI 程序需自行准备；首次执行先离线检查 `-h` 输出是否提供所有必需参数，不支持则失败，不回退到宽松参数。`--list-tools` 只检查程序是否可找到，不能证明版本兼容。Windows 使用原生 `.exe`，不通过 `.cmd`、PowerShell 或 shell 拼接执行。

搜索凭据只从配置的环境变量名读取，例如 `$env:EXA_API_KEY` 或 `$env:PERPLEXITY_API_KEY`。切换 provider 时可省略 `api_key_env`，使用对应默认名称。Caido 需要操作者已准备的服务及 `$env:CAIDO_TOKEN`；不自动启动服务或进行 guest 登录，不需要 Caido Python SDK。

外部工具和服务全部默认关闭。离线知识与记录默认可用，可以在主配置或扩展 YAML 中设置：

```yaml
extension_tools:
  knowledge_enabled: false
  workspace:
    enabled: false
```

工作记录默认放在证据目录下的 `workspace/records.sqlite3`，也可配置 `extension_tools.workspace.directory`。记录目录由操作者配置，模型只能使用记录 ID。新会话隔离，恢复同一会话 ID 继续使用原记录；子目标各自隔离。扩展 YAML 仅替换明确提供的扩展工具一级配置项，保留未覆盖的工作记录配置。

## 参数和流程

先 `tool_catalog` 搜索并 `select` 工具，再按照返回的 Schema 调用。例如 ffuf/naabu 的原生参数为：

```json
{"target":"https://example.com", "paths":["api/status","robots.txt"]}
```

```json
{"target":"example.com", "ports":[80,443]}
```

扫描器不接受任意 flags、字典路径或命令。实际工具参数固定为单并发、受控间隔和有限数量；主动探测仍需 L2 解锁和逐项确认。Subfinder 固定使用 hackertarget 的 HTTP 被动来源，设置全局及来源限速，并遵守 L0 调用间隔；不会启用默认的多来源并行枚举，结果不能证明完整覆盖。配置的二进制是可信连接器，CLI 参数限制不能代替操作系统或网络沙箱；范围过滤也不等于控制程序所有内部网络行为。

Nuclei 模板只接受一个 HTTP GET/HEAD、一个以 `{{BaseURL}}/` 或 `{{RootURL}}/` 开头的固定路径和简单 matcher。拒绝 raw、payload/fuzz、DSL、代码、DNS/network、headless、flow、外部动态地址等；禁重定向、interactsh 和自动更新。示例 `tools/data/nuclei-readonly-status.yaml` 仅观察 HTTP 状态，绝不能把命中解释为漏洞。

浏览器沿用 `browser` MCP 的导航、快照和请求白名单。读取 `browser_network_requests` 后，把本地 `evidence_id` 传给 `api_recon.runtime_evidence_ids`。Caido `list_requests` 的证据 ID 同样可导入。Caido `list_sitemap` 从有限请求页推导，`complete=false`，需要用 `after` 分页继续查询；它不是全量站点地图。

笔记和威胁模型使用 `action`（create/get/list/update/delete）、`record_id`、`title`、`content`。覆盖记录另有 `surface`、`risk_area`、`outcome` 和 `evidence_ids`。发现必须引用同目标有效证据，并保存 `severity` 和 `status`（candidate/observed/verified）。`verified` 是录入者声明，程序只校验引用归属，不能自动证明漏洞成立。缺少或外目标证据会拒绝。

每次记录动作都保存当前快照和 SHA256。SQLite 事务保证修订/删除原子化，证据写失败会回滚。报告按照持久执行日志顺序读取本会话最新快照，还原完整数据；最新快照无法验证时不会回退到旧发现，其他会话快照被忽略。修订前或已删除记录不作为当前发现，原始审计证据仍保留。最终任务建议调用 `workspace_snapshot`，明确覆盖缺口。

## 验证边界

新增测试使用假 CLI、模拟传输和临时存储，验证参数、门控、证据、取消、范围、恢复和报告；不连接真实目标、付费服务或运行 Docker 扫描。实际外部二进制版本、API 凭据与 Caido 服务仍需在准备好环境后验证。

2026-10-09 测试清理后的验证结果：完整 Python 回归 626 项通过，TUI 36 项通过，无排除项。Nmap 降级测试已改为离线桩，保留真实参数转换与降级标注验证。初次接入时外部适配器单独复验 38 项通过，离线 wheel 构建和包内 6 份知识资源读取通过。代码审查发现的 ffuf JSONL、被动来源限速、远程超时不确定性、记录快照顺序与会话隔离问题均已修正。

## 来源

工具与资料的参考来源、版本和许可证见 [归属说明](../tools/data/skills/NOTICE.md)。本项目使用原生适配和重新编写的 Recon 资料，不引入上游 Agent 运行时。
