# 当前项目架构

实际 Python 项目位于仓库的 `recon-agent V1.0/`，安装与打包入口为 `pyproject.toml`。
这份文档描述当前维护路径；旧路径的兼容入口不作为新增代码的位置。

## 目录与职责

```text
cli/                           启动、配置和界面适配
  main.py                      CLI 参数与模式选择
  launcher.py、setup_tools.py   本次进程配置与可选工具选择
  session.py                   Rich/文本会话
  session_commands.py          操作者命令
  tui_bridge.py                认证本地通信
  tui_session.py、tui_setup.py  TUI 会话与配置适配
  tui/                         JS 页面、布局、桥接与 npm 依赖清单
core/
  session_factory.py           共用的会话创建入口
  prompts.py                   提示词加载及动态信息组装
  prompt_templates/session.md  当前会话的默认主提示词
  orchestration/               Agent 决策、授权、执行、评估和持久化
model/
  lazy.py                      延迟初始化模型；启动时不发模型请求
  service.py                   模型调用、流式转发、用量与费用登记
  base.py、registry.py          模型契约、路由与 fallback
  litellm_adapter.py、cost.py   提供商适配、费用处理
tools/
  base.py                      工具参数与结果契约
  registry.py                  注册、Schema 披露与执行守卫
  runtime/                     工具目录、等待/超时、证据与产物
  builtin/                     项目自带工具及 nmap/httpx 等封装
  adapters/                    自定义命令、脚本、HTTP、外部 MCP 和配置
  techniques/                  指纹、爬取、JS/API 提取等复用手段
  data/                        字典与工具配置示例
collectors/                    确定性流程的资产聚合与收集
gate/、security/               授权等级、目标范围与扫描约束
efficiency/                    预算、上下文压缩与去重
hallucination/                 证据绑定、冲突与一致性检查
output/                        报告构建、保存与差异
platforms/                     平台路径、子进程与同步工作进程
server/                        向外提供 MCP 服务
scripts/                       确定性扫描与辅助脚本
knowledge/、observability/     CVE/快照、指标
utils/                         配置、日志和缓存
tests/                         Python 与 JS 测试；tests/tui/ 含模拟前端
```

## 会话主链路

`cli.main` 选择 TUI 或 Rich。两种界面调用 `core.session_factory.create_session_runtime` 创建同一套 gate、registry、LazyLLM 和 SessionRuntime，再负责输入与显示。创建过程不调用模型或扫描工具；进入运行时后创建/恢复 SQLite 状态，等待操作者任务。

模型调用经过 `model.lazy → model.service → model.registry → 提供商适配器`。
`core.prompts.session_prompt` 读取默认主模板或 `SESSION_PROMPT_FILE`，再注入授权目标和工具简介。运行时在发送模型请求前组装实际门控状态、上下文和工具 Schema。

`core.orchestration.model_context.prepare_context` 估算完整请求的上下文占用，包含主提示词、动态任务信息、会话消息和工具 Schema。默认容量为 100,000 tokens，达到 70% 时压缩较早的模型回复和工具结果；保留操作者指令、最近交互以及任务和证据索引。压缩后的工作上下文和读取游标单独保存，原始会话、证据与产物仍保存在持久层。下一轮和恢复会话接续压缩后的工作上下文，避免重新加载全部历史。

`efficiency.budget_guard` 仅检查费用上限。累计 token 用量用于统计，不限制任务；旧会话中的 token 上限和旧 `MAX_TOKENS_PER_TASK` 配置不再生效。界面显示当前上下文和压缩记录，不展示累计 token、金额或费用预算额度。容量与阈值可以通过 `CONTEXT_BUDGET`、`COMPACT_TRIGGER_RATIO` 或 CLI 参数修改。若必须保留的内容仍超过容量，运行时暂停并提示 `context_limit`，由操作者调整内容或新建任务。

Agent 主循环为 `decide → validate → authorize → execute → evaluate`。需要输入、授权或恢复处理时暂停；工具结果回到模型，模型可继续多步调用。

工具执行经过 `ToolRegistry.execute`，继续使用 Schema、范围和门控检查。
`tools.runtime.execution_wait` 管理等待、超时和清理；结果、证据与可分页产物由 `tools.runtime.result_payload`、`evidence_store` 和 `evidence_tools` 处理。完整会话及执行记录由 `core.orchestration.store` 和 SQLite checkpoint 保存。

## 其他运行模式

- 默认确定性模式：`cli.pipeline → collectors/工具 → output`。部分收集仍直接调用工具，并未全部统一到注册表；统一执行入口属于后续行为调整。
- 级联扫描：`scripts.full_scan` 等复用工具注册表和报告构建。
- 向外提供 MCP：`server.mcp_server → server.tools_bridge → ToolRegistry`。
- 接入外部 MCP：`tools.adapters.mcp_tools → tools.adapters.mcp_client → 外部服务器`。

## V1.0 新增能力

### 1. Template-based Vulnerability Verification
新增 Nuclei 兼容模板验证引擎，支持 YAML 格式模板，单次 GET/HEAD 请求，匹配器支持 status/word/regex 三种类型，离线验证零网络，可扩展社区模板。

### 2. Data Source Expansion
新增 8 大威胁情报数据源聚合：FOFA、Quake、ZoomEye、微步在线、ThreatBook、Shodan、Censys、BinaryEdge。统一 `DataSourceQueryTool` 接口，可配置 API Key 进行并发查询，聚合资产信息。

### 3. Externalized Fingerprint Library
新增 `tools/data/fingerprints.yaml` 指纹库，热加载支持，兼容 WhatWeb/Nuclei/Wappalyzer 格式。社区可直接在 YAML 中添加新特征，无需修改 Python 代码。

### 4. Headless Web Crawler
新增 `web_crawler` 工具，基于 Playwright/Chrome Headless，支持 SPA 渲染、JS 执行、表单提交、API 端点发现、链接/邮箱/注释提取。L2 级工具，需三级门控确认。

### 5. Local Model Support
新增 `LocalModelAdapter`，支持 Ollama / LM Studio / llama.cpp server 零网络离线推理。配置 `model: local/llama3:8b` 或 `model: ollama/qwen2.5:7b` 即可使用本地模型，无需 API Key。

```text
模型选择：
- openai/gpt-4o-mini (默认，远程 LiteLLM)
- ollama/qwen2.5:7b (本地 Ollama)
- local/llama3:8b (本地 llama.cpp)
- custom_endpoints (自定义端点)
```