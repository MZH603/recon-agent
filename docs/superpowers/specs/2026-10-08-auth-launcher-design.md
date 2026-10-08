# 启动配置页设计

用户已确认：裸启动 recon-agent.exe 先进入配置页，配置 API 与目标后进入现有会话；API Key 仅本次进程使用。保留已有参数启动命令。继续实现，不需要重复请求用户批准相同方案。

## 入口与流程

- 交互终端执行裸命令，先进入 Pi TUI 配置页；增加 --auth 可以显式打开该页面并与 --ui rich/pi/auto 配合。旧的 -t、--session、--resume、--mcp、--doctor、--version、--help 行为保留，携带既有业务参数的命令不会突然变成配置页。
- 填写 API 根地址、模型、API Key、目标域名/IP/URL/CIDR；明确勾选本次目标的合法授权，提交后在 L0 进入现有 LangGraph 会话并等待任务。不运行确定性流水线、不自动测试模型连接、不自动扫描。
- 缺少 Pi 依赖时 auto 回退 Rich 逐项输入（Key 隐藏）；--ui pi 明确报依赖错误。非 TTY/--batch 不进入交互页，也不从管道读取 Key，明确提示使用已有完整参数命令。Ctrl+C/退出恢复终端，退出码分别 130/0，不创建后台运行任务。
- Pi 页面支持 Tab/Shift+Tab 切换字段、单行编辑/粘贴、授权开关、进入会话按钮、错误提示。Key 输入始终遮罩，不通过聊天 Editor/history、Markdown、剪贴板复制命令或日志呈现；窄终端和中文字符可正确显示。
- 可使用两个连续且受控的 Pi 生命周期：先配置页，成功提交后清空并关闭配置页，再启动现有会话界面。避免大规模改写现有会话生命周期。

## 预填与确认值

- 非敏感配置保存在 get_config_dir()/launcher.json，只含 api_base、model、target；不含 API Key、授权、扫描级别或完整 Settings。原子写入，并验证加载类型/长度；损坏文件退回默认值，不输出文件原文。
- 预填优先级：显式 --model/-t > 非空 RECON_MODEL/RECON_API_BASE 与现有主模型凭据 > 上次 launcher 非敏感字段 > 现有 YAML 的非敏感默认字段。无上次目标时以 example.com 为占位说明，不默认授予它授权。
- Key 仅在 Python 内存中预填，来自 RECON_API_KEY 或现有 Settings/引用的环境变量。前端只接收“已有 Key 可用”的布尔状态，不接收已有 Key 明文。Key 留空则沿用已有内存 Key；输入新 Key 则用于本次启动。没有 Key 可给出表单错误，本阶段仅支持带 Key 的 OpenAI 兼容 API。
- 配置页确认后的 model/api_base/api_key 是本次会话的明确主连接，不能再被旧 RECON_* 覆盖；备用模型仍使用独立配置。裸模型名在配置页规范化为 openai/模型名，已有供应商前缀保持原样。已有带参数启动的环境变量优先规则不变。

## 校验与凭据生命周期

- Python 校验非空/合理长度字段、http/https 根地址（不含账号密码或查询 fragment，不接受完整 /chat/completions 路径）、目标格式及现有目标保护规则；不把用户输入原文写进错误说明。授权必须为 true 才可提交，校验失败停留页面并可修改。
- 配置阶段使用现有认证环回 TCP JSONL 的单独严格命令 schema，仅允许提交配置、退出/取消；配置结束之后不能用配置命令改变运行期授权。运行期 receive 的既有严格 schema 不放宽。
- 用户新输入的 Key 只从前端短暂内存经本地认证桥传入 Python；成功/退出时清空输入组件及其撤销、粘贴缓存等记录。Key 不进入环境变量、子进程参数、配置文件、SQLite checkpoint、模型 messages、报告、日志、错误或恢复命令。Python 使用现有 SecretStr/排除序列化语义保存主连接。
- 启动页不是扫描升级授权；原有 L1/L2 门控及会话内确认保持不变。

## 组件边界

- cli/launcher.py：预填、单次配置结果与校验、非敏感存储、Rich fallback。
- cli/pi_setup.py：配置页桥接和前端生命周期。cli/pi/setup.mjs 与 setup-app.mjs：仅配置页呈现和单次提交。
- cli/main.py：裸命令/--auth 路由；model/registry.py、core/llm.py、cli/session.py、cli/pi_session.py：仅增加可选显式连接传入，旧调用保持兼容。
- cli/pi_bridge.py：增加独立配置阶段的读取校验，不改变运行期命令 schema；pyproject.toml 添加两个生产资产，不打包测试或 node_modules。

## 验收

测试先失败再实现，全部使用本地 fixture。验证裸命令进入等待任务会话且无模型/扫描调用、旧模式不变、非交互拒绝交互、表单与 Key 遮罩/清空、授权与字段校验、RECON_* 自动预填和确认值优先、持久文件不含 Key/授权、实际 Pi 输入和 TCP 配置 roundtrip、退出/异常终端及子进程清理。执行现有 Python 离线回归与 Node 测试，构建 wheel 检查新增生产资产；使用 Windows ConPTY 验证裸命令入口与取消。
