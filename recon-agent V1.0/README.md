# recon-agent V1.0

授权安全测试的信息搜集工具，提供确定性采集、受控级联、LangGraph 交互会话与 MCP 接入。工具结果通过代码层 Schema、合规、范围、门控及预算校验，输出带来源的 Markdown、JSON、CSV 报告。

仅用于已获合法授权的目标。L0 是受控采集级别；HTTP 指纹、探活和证书 SAN 查询可能向远端发请求，不能理解为全部纯被动。

[使用说明书](docs/使用说明书.md) · [项目说明书](docs/项目说明书.md) · [知识骨架](docs/知识骨架.md)

## 安装与启动

Python ≥ 3.10。核心依赖由 `pyproject.toml` 安装，包括 LiteLLM、LangGraph 和 SQLite checkpoint 支持。

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
# Linux 对应 .venv/bin/python

# 默认确定性采集：自动运行，不依赖模型
recon-agent -t example.com --authorized --batch

# 会话启动仅创建状态并等待输入：没有模型调用或工具扫描
recon-agent --session -t example.com --authorized
```

可以只用环境变量指定模型、API 请求根地址和 Key，无需修改 YAML。在仓库根目录打开 PowerShell：

```powershell
Set-Location '.\recon-agent V1.0'
$env:RECON_MODEL="openai/your-model"
$env:RECON_API_BASE="https://your-endpoint.example/v1"
$env:RECON_API_KEY="你的 Key"
& '..\.venv\Scripts\recon-agent.exe' --session -t example.com --authorized
```

上例使用仓库根目录已有的 `.venv`。模型选择优先级为 `--model` > 非空 `RECON_MODEL` > YAML `name`。
非空 `RECON_API_BASE`、`RECON_API_KEY` 分别覆盖所选主模型的 YAML 地址和凭据，命名端点也适用；
它们不覆盖 `fallback` 的模型、地址或 Key。变量未设置或全为空白时保留原配置；模型名和地址去除两端空白，Key 保留原内容。
修改环境变量后退出并重新启动会话（可用会话 ID 恢复）。

也可直接在 `config.yaml` 中填写连接。例如 OpenAI 兼容的自定义端点：

```yaml
model:
  provider: litellm
  name: openai/your-model
  api_base: https://your-endpoint.example/v1
  api_key: "填写你的 Key"
  # api_key_env: CUSTOM_API_KEY  # 可选；api_key 为空时读取
  fallback: []
```

`api_base` 填 API 根地址（一般以 `/v1` 结尾），不要填完整 `/chat/completions` 路径。
`provider: litellm` 选择适配器；OpenAI 兼容端点的 `name` 使用 `openai/模型名` 选择协议。
未设置非空 `RECON_API_KEY` 时，非空 `api_key` 优先于 `api_key_env`；空字符串或空白 Key 视为未填写。
也可以设置 `api_key: ""`、`api_key_env: CUSTOM_API_KEY`，然后在 PowerShell 执行
`$env:CUSTOM_API_KEY="你的 Key"`。指定环境变量但未设置、又没有直接 Key 时，该模型会报错或被 fallback 链跳过；
两个凭据字段都不配置时，保留 LiteLLM 自己读取供应商环境变量的行为。

`--model openai/another-model` 使用主连接的地址和凭据；`--model deepseek` 等命名端点命中
`custom_endpoints` 的 `name` 或 `model` 时，先使用该端点自己的连接配置，再应用非空 `RECON_API_BASE`、`RECON_API_KEY`。
旧端点字段 `base_url`、`api_key_env` 继续支持；端点也可填 `api_base`（优先于 `base_url`）和 `api_key`。
`fallback` 每项使用匹配端点的独立连接，或供应商的默认连接与环境变量，不继承主模型地址和 Key。
修改 YAML 或环境变量后退出并重新启动会话（可用会话 ID 恢复），让新进程重新加载配置。
直接 Key 不写入配置对象的显示/导出、会话或报告；包含真实 Key 的 YAML 请保留在本机，不要提交到版本库。

模型到第一条任务才初始化，配置或连接失败会暂停，允许报告、退出并恢复；会话不会自动运行默认流水线。

## 交互会话与恢复

启动打印会话 ID 和恢复命令。在 `recon>` 输入中文或自然语言任务，例如“仅查询 example.com 的 A 记录，然后总结来源”。回复待确认问题时恢复当前节点。仅在显式任务之后才可能调用模型或工具。

```powershell
recon-agent --session --resume SESSION_ID -t example.com --authorized
recon-agent --session -t example.com --authorized -o reports --output-format json
```

恢复要求已有 checkpoint、相同目标及重新声明授权。状态数据库位于 Windows `%APPDATA%\recon-agent\agent_state.sqlite`，Linux `$XDG_CONFIG_HOME/recon-agent/agent_state.sqlite`（默认 `~/.config`）。同一会话同时只允许一个进程持有。

| 输入 | 行为 |
|---|---|
| `状态` / `status` | 查看级别、计划、累计用量和待回复问题 |
| `报告` / `report` | 保存当前证据；暂停时也不调用模型或继续扫描 |
| `stop` | 取消当前任务，继续等待新任务 |
| `abort` | 取消当前任务并退回 L0，继续等待；本进程不再升级 |
| `quit` / `退出` / EOF | 保存并关闭，保留待确认节点 |
| Ctrl+C | 安全关闭；未完成执行保留为恢复/不确定状态，不自动重试 |

每个新进程从 L0 开始，`--level`/`--profile` 不预先授予会话权限。L1 需一次确认；L2 依次输入 `CONFIRM 2`、目标精确串、`I UNDERSTAND AND AUTHORIZE`，并逐动作确认。重启后重新确认。`--batch` 或非 TTY 永久禁止 L2；`--auto-confirm` 不替会话填写确认码。`--resume` 必须与 `--session` 搭配，会话不能与 `--mcp` 搭配。

报告始终保存三种格式，`--output-format` 选择控制台展示的文件，`-o` 指定目录。JSON 保存完整状态、工具 data/stdout/stderr、来源及哈希、失败、事件、冲突和执行日志。相同秒生成也不覆盖。模型摘要标为未验证分析；冲突观测保留双方；未完成/降级结果带水印。费用记录已知金额与未知定价调用数，未知价格时不能证明精确费用上限，token 预算仍受约束。

## 架构与阶段边界

```text
CLI --session → 空闲 REPL → SessionRuntime (core/orchestration/)
  decide → validate → authorize [interrupt] → execute → evaluate
  ask_user/update_plan/finish_task · bounded decisions/actions/steps
  SQLite checkpoints + independently committed usage/execution journal
  dynamic ToolRegistry (12 tools) → code guards → full evidence reports
CLI default/cascade → existing deterministic pipeline/scripts
MCP → existing external-agent tool bridge (L2 prohibited)
```

模型提出工具与计划；代码决定是否允许执行。原始工具输出是非可信数据；成功工具来源才能支持完成任务，无证据解释标 `[无证据]`。模型失败、Schema 重试耗尽、预算耗尽及矛盾都可暂停。执行已开始但没有完成日志时，恢复必须显式选择 retry/skip；L2 重试也重新逐项确认。

本阶段只替换交互会话编排、持久化与报告适配，保留默认/级联/MCP 路径。Skill、RAG、工具组合与 MCP 标准升级属于后续阶段。旧 `core/agent.py` 保留用于兼容，不再是 `--session` 主循环。

## 离线验证

```powershell
.venv\Scripts\python -m pytest tests -q --ignore=tests/unit/test_nmap_fallback.py -k "not golden_08"
```

上述选择排除现有联网探测测试；会话测试使用脚本模型和离线工具，验证启动零调用、持久化、门控、报告、恢复与费用记账。
