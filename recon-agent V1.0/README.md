# recon-agent V1.0

授权安全测试的信息搜集工具，提供确定性采集、受控级联、LangGraph 交互会话与 MCP 接入。工具结果通过代码层 Schema、合规、范围、门控及预算校验，输出带来源的 Markdown、JSON、CSV 报告。

仅用于已获合法授权的目标。L0 是受控采集级别；HTTP 指纹、探活和证书 SAN 查询可能向远端发请求，不能理解为全部纯被动。

[项目架构](docs/architecture.md) · [扩展工具接入](docs/tool-integrations.md) · [使用说明书](docs/使用说明书.md) · [项目说明书](docs/项目说明书.md) · [知识骨架](docs/知识骨架.md)

## 安装与启动

Python ≥ 3.10。核心依赖由 `pyproject.toml` 安装，包括 LiteLLM、LangGraph 和 SQLite checkpoint 支持。

交互会话默认使用 TUI 主屏终端界面（`@earendil-works/pi-tui` 精确版本 1.0.4），需要 Node.js ≥22.19.0。
在项目目录执行 `npm ci --ignore-scripts --prefix cli/tui`；wheel 安装后可用
`python -c "from cli.tui_bridge import TUI_DIR; print(TUI_DIR)"` 找到该目录，再切换到该目录执行 `npm ci --ignore-scripts`。
依赖只安装在本机该目录，不自动联网安装。模型、LangGraph、门控和 SQLite 仍由 Python 后端负责；已有 Key 只留在 Python，配置页中新输入的 Key 仅短暂经认证本地桥传给 Python。

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
# Linux 对应 .venv/bin/python

# 裸启动：配置 API 根地址、模型、Key、目标，并确认本次授权
recon-agent
# Windows 仓库已有虚拟环境的入口（在项目目录）
& '..\.venv\Scripts\recon-agent.exe'
# 显式打开配置页，或者选择 Rich 隐藏 Key 的兼容输入
recon-agent --auth --ui rich

# 默认确定性采集：自动运行，不依赖模型
recon-agent -t example.com --authorized --batch

# 会话启动仅创建状态并等待输入：没有模型调用或工具扫描
recon-agent --session -t example.com --authorized
```

裸启动必须使用交互终端。TUI 配置页用 Tab/Shift+Tab 切换，Enter 前往下一项，
Space/Enter 勾选本次授权，最后在“进入会话”按钮按 Enter；Esc 退出，Ctrl+C 取消。
配置页还有折叠的“扩展工具（可选）”区域：可直接使用示例列表勾选工具，也可填写本地 YAML 路径并加载后选择。工具条目显示最低级别及程序/脚本准备状态；浏览器 MCP 需在 YAML 中填写已安装的入口脚本路径。无需扩展时直接进入会话；折叠或选择“跳过扩展配置”会取消本次页面选择，沿用已有配置。选择仅本次进程有效，不写入 `launcher.json`。Rich 兼容界面的可选 YAML 提示留空即可跳过，输入 `/example` 可使用示例。

配置确认后从 L0 等待任务，不自动测试 API 连接或扫描。`--auth --lab` 可配置自有内网实验目标，
政府/军事域名和链路本地地址仍拒绝；L1/L2 的原有会话内确认保持不变。

API Key **仅本次进程使用**，配置页始终遮罩；已有 Key 不发送给前端，留空会沿用 Python 内存中的 Key。
非敏感 API 地址、模型和目标原子保存到用户配置目录的 `launcher.json`，只含这三个字段。
Key、授权和扫描级别均不保存，每次启动重新确认授权。预填优先级为显式 `--model/-t`、非空
`RECON_MODEL/RECON_API_BASE`、上次非敏感字段、YAML 默认值；Key 来自现有主模型凭据或
`RECON_API_KEY`。提交的主连接在本次会话内优先于旧环境变量，备用模型继续使用独立配置。
配置页自动将裸模型名补成 `openai/模型名`，带供应商前缀的模型保留原值。

`--ui auto` 缺少 TUI 依赖时回退 Rich；`--ui tui` 明确报告缺少依赖。原有 `--ui pi` 作为兼容别名继续可用。
非 TTY 或 `--batch` 不进入配置页，也不会从管道读取 Key；请使用现有完整参数命令。
已有 `-t`、`--session`、`--resume`、`--mcp`、`--help`、`--version`、`--doctor` 行为保留；
`--auth` 与 `--mcp` 不兼容。

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

DeepSeek 的 OpenAI 兼容连接示例：`RECON_MODEL=openai/deepseek-flash`、
`RECON_API_BASE=https://api.deepseek.com/v1`，Key 使用 `RECON_API_KEY`。
`openai/` 指定请求协议，发送给服务器的模型名仍是 `deepseek-flash`。
裸模型名可能无法被 LiteLLM 识别。出现“跳过备用模型 deepseek-chat”表示 YAML 的
fallback 缺少自己的 `DEEPSEEK_API_KEY`；不表示主模型的 `RECON_API_KEY` 缺失。
主模型可继续使用自己的连接；备用模型仍需独立配置。

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

正常交互终端的 `--ui auto` 默认选择 Pi：提交任务立即显示底部加载态，回答和问题逐段 Markdown 展示；Editor 支持多行（Shift+Enter）和上下键历史。工具执行显示状态，已预览答案/问题在终态去重。完整工具参数通过校验前不会执行；工具 JSON、XML 控制块、推理标签和终端控制字符不会直接出现在回复预览中。Ctrl+C 取消并以 130 退出；界面断开也会取消任务并保存已消耗用量，不继续后台执行。

助手正文和 `ask_user.question` 随 API 响应增量预览，首段无需等待完整工具调用。支持 `reasoning_content` 的模型先显示“模型思考中 · 已接收 N 字符”，答案到达后切换为流式回复；这里统计的是字符，实际 token 用量按 API usage 结算。思考原文不发送到 Pi，但作为模型协议字段保留在会话历史中，供后续工具请求回传。DeepSeek 默认思考阶段本身可能耗时，界面不能提前显示服务端尚未返回的答案。

会话持续多轮调用模型和工具，普通工具失败交给模型调整方法。唯一正常结束标记是助手正文最后独立一行 `<task_complete/>`；代码块、推理、工具输出中的标记无效，含工具调用的回复先执行调用。未输出标记时继续决策，异常循环到段上限时保存并暂停。

TUI 宽屏左侧显示对话、右侧显示上下文占用、费用、任务计划、证据与产物；窄屏折叠侧栏。F2 或 `/sidebar` 切换侧栏，PgUp/PgDn 浏览，F3 或 `/details` 展开工具详情。默认暗色青绿主题，`TUI_THEME: light` 适配浅色终端，`NO_COLOR` 禁用配色。

未返回的工具保持执行中，显示已等待秒数和最大等待时间，不凭无输出判断错误。全局默认 120 秒，取消清理最多额外 5 秒；逐工具覆盖优先，其次工具既有配置，再使用全局值。截止后向模型返回 `TOOL_TIMEOUT` 并保留已有输出。远端或未确认停止的执行标为结果未知，相同动作需明确 retry/skip；跳过也保留未知记录。迟到结果只保存诊断，不覆盖超时结算。

以下项可加在项目 `config.yaml` 顶层；修改后重新启动：

```yaml
TOOL_TIMEOUT_SECONDS: 120
TOOL_CLEANUP_SECONDS: 5
TOOL_TIMEOUT_OVERRIDES:
  system_scan: 180
TOOL_RESULT_MAX_BYTES: 16000
CONTEXT_BUDGET: 100000
COMPACT_TRIGGER_RATIO: 0.70
MAX_COST_PER_TASK: 2.0
TUI_THEME: dark  # dark / light
SESSION_PROMPT_FILE: ""  # 可选的主提示词 UTF-8 文件路径
```

最大等待时间必须为有限正数。大结果完整保存为真实 JSON 产物，模型收到摘要及 ID，使用 `artifact_read(target, artifact_id, offset, max_bytes)` 分页读取；`evidence_get` 同样支持偏移读取。主提示词覆盖文件也应保留持续执行、证据和 XML 完成约束，工具说明及真实预算/授权上下文由运行器追加。

`--ui rich` 使用已有 Rich 兼容界面；`--ui tui` 明确要求 TUI 依赖可用。`auto` 缺少本地依赖时会明确提示并回退 Rich，`tui` 则给出安装提示并退出。输出重定向、非 TTY、dumb terminal 或 `--batch` 使用已有纯文本路径，界面选择不会改变原有授权和 L2 门控。

首块前的连接错误可以重试或切换备用模型；响应已经开始后断流会暂停，已显示片段标为未完成，需要显式继续。Ctrl+C 保留退出码 130 和恢复命令，关闭模型流并释放会话锁。完整调用只计量一次；断流或取消保存已知 token 或保守估算，未提供 usage 的成功流也估算 token，费用无法确定时计入未知调用。流式观察事件仅在当前进程内用于界面展示，不写入 checkpoint 或授予权限。

```powershell
recon-agent --session --resume SESSION_ID -t example.com --authorized
recon-agent --session -t example.com --authorized -o reports --output-format json
```

恢复要求已有 checkpoint、相同目标及重新声明授权。状态数据库位于 Windows `%APPDATA%\recon-agent\agent_state.sqlite`，Linux `$XDG_CONFIG_HOME/recon-agent/agent_state.sqlite`（默认 `~/.config`）。同一会话同时只允许一个进程持有。

| 输入 | 行为 |
|---|---|
| `状态` / `status` | 查看级别、计划、累计用量和待回复问题 |
| `报告` / `report` | 保存当前证据；暂停时也不调用模型或继续扫描 |
| `/new` | 保存旧任务及历史，开启新任务及上下文；不自动调用模型或扫描 |
| `/budget cost 1` | 追加当前任务 USD 1 费用上限；不清零已用量，费用允许后恢复 |
| `stop` | 取消并保存当前任务，普通追问仍属于当前任务 |
| `abort` | 取消当前任务并退回 L0，继续等待；本进程不再升级 |
| `quit` / `退出` / EOF | 保存并关闭，保留待确认节点 |
| Ctrl+C | 安全关闭；未完成执行保留为恢复/不确定状态，不自动重试 |

每个新进程从 L0 开始，`--level`/`--profile` 不预先授予会话权限。L1 需一次确认；L2 依次输入 `CONFIRM 2`、目标精确串、`I UNDERSTAND AND AUTHORIZE`，并逐动作确认。重启后重新确认。`--batch` 或非 TTY 永久禁止 L2；`--auto-confirm` 不替会话填写确认码。`--resume` 必须与 `--session` 搭配，会话不能与 `--mcp` 搭配。

报告始终保存三种格式，`--output-format` 选择控制台展示的文件，`-o` 指定目录。JSON 保存完整状态、工具 data/stdout/stderr、来源及哈希、失败、事件、冲突和执行日志。相同秒生成也不覆盖。模型摘要标为未验证分析；冲突观测保留双方；未完成/降级结果带水印。费用记录已知金额与未知定价调用数，未知价格时不能证明精确费用上限。累计 token 仅用于计量，不再作为任务上限。

普通消息（包括完成后的追问）继续同一任务，只有 `/new` 开启新任务。上下文容量默认 100,000 tokens，达到 70%（约 70,000）时自动压缩旧回复和工具结果后继续，完整历史与证据不删除。当前请求估算包含系统提示、动态上下文和工具 Schema，与累计调用消耗分开；侧栏显示占用、压缩次数与最近节省量。可用 `--context-tokens`、`--compact-ratio` 或上述 YAML 配置修改。

界面只展示当前上下文占用与压缩情况，不展示累计 token、金额和费用预算额度。费用仍在后台按任务计账，达到费用硬上限暂停；用 `/budget cost USD` 追加。旧 `MAX_TOKENS_PER_TASK` 和 `--max-tokens` 不再限制执行，旧数字形式 `/budget tokens [USD]` 会提示新用法。旧会话恢复时忽略 token 上限。后台用量采用服务商 usage，缺失时标记为估算。

压缩保留系统提示、用户指令、最近对话及完整工具调用/返回组。若这些必须保留的内容和工具 Schema 本身超过容量，会明确提示上下文过大，需精简输入或开启 `/new`，不会误报预算耗尽。

## 架构与阶段边界

目录按职责组织，运行代码与测试分开；详细调用关系见[项目架构](docs/architecture.md)：

```text
cli/
  main.py                 # CLI 启动入口
  tui_bridge.py           # Python 与前端的本地通信
  tui_session.py          # 会话页面适配
  tui_setup.py            # 配置页面适配
  tui/                    # JS 页面、布局及前端依赖清单
core/
  session_factory.py      # TUI 与 Rich 共用的会话初始化
  prompts.py              # 主提示词加载与动态信息
  prompt_templates/       # 默认会话主提示词
  orchestration/          # Agent 主循环与持久化
model/
  lazy.py、service.py      # 延迟初始化、调用与预算登记
tools/
  base.py、registry.py     # 公共工具契约与注册执行入口
  runtime/                # 等待、超时、结果、证据与产物
  builtin/                # 自带工具及外部程序封装
  adapters/               # 自定义工具、HTTP、外部 MCP 与配置
  techniques/、data/       # 复用手段和静态资源
tests/
  smoke/                  # CLI 与真实 TUI 进程冒烟
  e2e/                    # 会话/报告/恢复与 MCP 采集端到端
```

`cli/tui/` 只包含运行代码及依赖，测试不进入 wheel。
底层终端库仍为 `@earendil-works/pi-tui`，项目自己的目录和入口统一采用 `tui` 命名。

```text
CLI --session → TUI / Rich → shared session factory → SessionRuntime
  decide → validate → authorize [interrupt] → execute → evaluate
  ask_user/update_plan · assistant <task_complete/> · bounded decisions/actions/steps
  SQLite checkpoints + independently committed usage/execution journal
  dynamic ToolRegistry → code guards + deadlines → evidence/artifacts/reports
CLI default/cascade → existing deterministic pipeline/scripts
MCP → existing external-agent tool bridge (L2 prohibited)
```

模型提出工具与计划；代码决定是否允许执行。原始工具输出是非可信数据；发现需要真实来源支持，普通问答可直接以 XML 标记完成。模型失败、Schema 重试耗尽、预算硬上限及矛盾都可暂停。执行已开始但没有明确完成日志时，恢复必须显式选择 retry/skip；L2 重试也重新逐项确认。

本阶段替换交互会话编排、持久化、报告适配与终端界面，保留默认/级联/MCP 路径。Skill、RAG、工具组合与 MCP 标准升级属于后续阶段。旧 `core/agent.py` 保留用于兼容，不再是 `--session` 主循环。

## 离线验证

受控扫描器、搜索、Caido 只读查询和工作记录已接入，配置与调用见 [扩展工具接入](docs/tool-extensions.md)。外部工具默认关闭。

```powershell
& '../.venv/Scripts/python.exe' -m pytest -q
npm --prefix cli/tui test
```

只维护冒烟与端到端测试，全部通过真实程序入口运行，使用临时配置和本地服务，无需模型 Key 或公网目标。pytest 完整命令包含 TUI 冒烟，需要先安装 Node.js 和 TUI 依赖；npm 命令仅运行 TUI 冒烟。目录约定、筛选命令和覆盖范围见 [测试约定](docs/testing.md)。
