# 工具集成

本项目增加了自定义命令、Python 脚本、HTTP 工具、外部 MCP（含浏览器）、JS/API 采集和本地证据查询。实现使用本项目的 Python 工具接口；工具调用继续经过目标范围、合规、级别门控、会话执行日志及报告流程。

受控 CLI、搜索、Caido 查询、知识和工作记录接入见 [扩展工具说明](tool-extensions.md)。

## 启动

裸启动或 `python -m cli.main --auth` 后，可以直接确认基础配置并进入会话，也可以展开“扩展工具（可选）”。页面默认展示现有配置中的扩展；没有配置时展示全部关闭的示例。用 Space/Enter 勾选需要的命令、脚本、HTTP 工具或 MCP；也可填写自己的 YAML 路径，选择“加载工具列表”后再勾选。修改路径后需要重新加载，避免提交旧列表。

列表显示程序/入口脚本是否存在以及最低执行级别。勾选只注册本次会话可使用的扩展，不安装依赖，也不执行任何工具。浏览器 MCP 仍需先准备服务与浏览器并在 YAML 中填写入口路径。基础内置工具，包括 `api_recon` 和证据查询，始终可用；是否能执行还受原有级别门控限制。

“跳过扩展配置”或折叠区域会取消本次页面选择并沿用已有配置；没做选择时可直接进入。修改勾选后全部取消，会明确关闭本次配置中的所有扩展。选择不保存到 `launcher.json`，YAML 原文件也不会被改写。Rich 界面在可选 YAML 路径处留空即可跳过；输入 `/example` 后用逗号分隔的编号选择，`/skip` 取消本次扩展配置。

以下命令方式仍可使用。在 `recon-agent V1.0` 目录执行：

```powershell
# 不需要目标、模型、网络或外部服务：查看内置工具和已配置的扩展
python -m cli.main --list-tools
python -m cli.main --tools-config tools/data/tool-integrations.example.yaml --list-tools

# 编辑一份配置，启用需要的工具，然后进入会话
Copy-Item tools/data/tool-integrations.example.yaml tools.local.yaml
python -m cli.main --session -t example.com --authorized --tools-config tools.local.yaml
```

也可把 `custom_tools`、`mcp_servers` 放在现有 `config.yaml`。`--tools-config` 只接收工具相关字段，不能用它改变扫描门控。该文件中出现的工具列表替换相应的主配置列表。没有扩展配置时不启动任何外部进程或 MCP 服务。

模型先看到一行工具简介。自定义工具和 MCP 参数按需披露：先调用 `tool_catalog`，用 `select` 指定工具名称，再使用对应 Schema。选择结果保存在会话中，恢复会话时沿用；L1/L2 授权仍在每次进程及每项动作上检查。

## 自定义工具

| 类型 | 配置 | 最低级别 | 行为 |
|---|---|---|---|
| command | `command` 参数数组 | L2 | 直接启动可执行程序，不经过 shell |
| script | `script` Python 源码 | L2 | 复用 AST、Bandit 和运行时隔离检查 |
| http | `url`、`method` | L1 | 仅 GET/HEAD，检查目标、解析地址和重定向 |
| shell | `command` | L0 | 提供人工命令提示，不自动运行 |

调用参数统一为 `{"target":"example.com","arguments":{...}}`。`input_schema` 定义 `arguments`，并在代码层验证。模板仅支持 `{target}` 和已声明的标量参数；参数数组中的每个元素独立替换。不要配置 `cmd /c`、PowerShell `-Command` 或其他能把参数重新解释为代码的启动器。

`response_format` 支持 `text`、`json`、`jsonl`。超时及输出字节上限可配置；截断会明确标记。`env` 把子进程变量名映射到现有环境变量名，`headers_env` 把 HTTP 请求头映射到环境变量名。配置里填写变量名，密钥在本机环境中设置。传出的这些凭据在结果中遮蔽。

脚本通过预置的 `RECON_INPUT` 读取 `{target, arguments}`，脚本源码由操作者在配置里提供。Bandit 必须可用；默认宿主机执行属于降级隔离，严格隔离需要启用并准备 Docker。脚本的源码静态检查和 L2 确认继续生效。

## 外部 MCP 与浏览器

支持 `stdio`、Streamable HTTP 和传统 SSE。连接在第一次 `mcp_tools` 或 `mcp_call` 时建立；退出会话会关闭连接并回收子进程。`mcp_tools` 返回已允许工具的参数 Schema；`mcp_call` 统一通过 L2 门控后调用。

每个服务必须设置 `allowed_tools`；空列表不允许调用任何远程工具。每个允许的工具都必须有 `target_fields` 映射，例如 `browser_navigate: [url]`。这些参数作为 URL/主机校验，不得超出当前授权范围。经人工检查、只读取当前页面状态的工具可以明确写 `browser_snapshot: []`；缺少映射会拒绝配置。避免把执行代码、任意文件访问、表单提交工具加入浏览器允许列表。

浏览器示例使用已安装的 Playwright MCP 的 `cli.js`，由 `node` 启动；先按其[官方说明](https://github.com/microsoft/playwright-mcp)准备服务和浏览器，再填写实际路径，启用 `browser` 配置。本项目不会自动安装 npm 包、下载浏览器或启动扫描。浏览器的 `--headless`、`--isolated` 参数见官方说明。

远程工具是操作者配置的可信连接器。本项目检查调用参数和授权目标，但外部程序内部请求、浏览器页面资源及重定向需要操作者额外限制；这些适配器不能充当操作系统或网络沙箱。一次浏览器连接只绑定一个授权目标，改变目标需要新会话。

远程完整返回（受字节上限约束）会保存在本地证据库，并保留在工具结果中，附证据 ID 与哈希。服务器错误按失败记录，工具调用不会自动重试；连接中断后的执行不确定性仍由现有会话日志处理。将程序路径、环境或服务器地址改好后，可离线列出工具，再在会话中发现远程 Schema。

## JS/API 采集与证据

`api_recon` 在 L1 下读取入口 HTML、关联 JS 和可识别的 webpack/Vite 懒加载资源，默认最多 8 次请求、每个资源最多 100 KB。只读取授权范围内的资源，检查重定向和实际解析地址，遵循现有请求间隔和总超时。资源数量、截断、失败和解析局限都会明确记录。静态解析每个资源最多处理 1000 个条目和 4096 字符的调用参数片段；运行时最多导入 1000 条请求样本，完整原始数据仍可按证据 ID 读取。

结果包含 API 的 `method`、`path`、`params`、`source`、`observed`，前端路由单独保存。未知方法保持为空；静态字符串只是候选，不能证明服务端接口存在或参数必填。Markdown、JSON、CSV 报告均保留这些结果。

浏览器运行时流程：先在 L2 下经 `mcp_call` 调用 `browser_navigate`，再读取 `browser_network_requests`；将返回的本地证据 ID 传给 `api_recon.runtime_evidence_ids`。采集器导入保存的请求记录，按来源区别真实请求观测与 mock 候选，不会自动执行 JS 或额外点击页面。一次请求记录也不能证明接口可访问。

`evidence_search` 按当前目标查询本地证据元数据，`evidence_get` 按 64 位十六进制 ID 读取有限大小的原始记录。证据包含 SHA256、大小和目标绑定；不能用工具读取任意文件路径。默认放在本机 recon-agent 证据目录，也可设置 `TOOL_EVIDENCE_DIR`。报告保留引用，完整会话结果保存在报告 JSON。有状态的 MCP 调用、自定义工具和 API 采集会重新获取结果，不因相同参数复用旧观测；同一次执行的崩溃恢复与不确定动作确认仍由日志保护。

示例会话任务：

```text
搜索 API 和 MCP 工具目录，披露所需工具参数。
在授权范围内采集首页和 JS，列出 API 候选与前端路由，保留来源。
如果需要运行时确认，先说明浏览器动作并等待 L2 门控。
将浏览器网络请求证据导入 API 采集，再生成报告。
```
