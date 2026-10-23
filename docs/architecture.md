# 当前项目架构

Python 项目位于仓库根目录，安装与打包入口为 `pyproject.toml`。
这份文档描述当前维护路径；旧路径的兼容入口不作为新增代码的位置。

## 目录与职责

```text
agent/
  cli/                    CLI 参数、配置、确定性流水线及文本会话
  core/                   Agent 主循环、会话工厂和提示词
  model/                  模型协议、适配和调用
  tools/                  工具契约、注册、内置工具和资源
  gate/、security/         授权等级、目标范围与扫描约束
  server/                 MCP 服务入口
  scripts/                确定性扫描与辅助脚本
  collectors/、knowledge/ 采集与知识处理
  efficiency/、output/    预算、上下文、报告与产物
  hallucination/          证据绑定、冲突与一致性检查
  platforms/、utils/      平台和通用设施
tui/
  *.mjs                   终端页面、布局与交互
  bridge.py               本地通信协议
  session.py、setup.py    界面会话与配置适配
third_party/tools/        上游第三方扫描器、二进制和字典
tests/                   冒烟、端到端与历史回归测试
docs/                    正式项目文档
```


## 会话主链路

`agent.cli.main` 选择 TUI 或 Rich。两种界面调用 `agent.core.session_factory.create_session_runtime`
创建同一套 gate、registry、LazyLLM 和 SessionRuntime，再负责输入与显示。
创建过程不调用模型或扫描工具；进入运行时后创建/恢复 SQLite 状态，等待操作者任务。

模型调用经过 `agent.model.lazy → agent.model.service → agent.model.registry → 提供商适配器`。
`agent.core.prompts.session_prompt` 读取默认主模板或 `SESSION_PROMPT_FILE`，再注入授权目标和工具简介。
运行时在发送模型请求前组装实际门控状态、上下文和工具 Schema。

`agent.core.orchestration.model_context.prepare_context` 估算完整请求的上下文占用，包含
主提示词、动态任务信息、会话消息和工具 Schema。默认容量为 100,000 tokens，
达到 70% 时压缩较早的模型回复和工具结果；保留操作者指令、最近交互以及任务和证据索引。
压缩后的工作上下文和读取游标单独保存，原始会话、证据与产物仍保存在持久层。
下一轮和恢复会话接续压缩后的工作上下文，避免重新加载全部历史。

`agent.efficiency.budget_guard` 仅检查费用上限。累计 token 用量用于统计，不限制任务；
旧会话中的 token 上限和旧 `MAX_TOKENS_PER_TASK` 配置不再生效。
界面显示当前上下文和压缩记录，不展示累计 token、金额或费用预算额度。容量与阈值可以通过
`CONTEXT_BUDGET`、`COMPACT_TRIGGER_RATIO` 或 CLI 参数修改。
若必须保留的内容仍超过容量，运行时暂停并提示 `context_limit`，由操作者调整内容或新建任务。

Agent 主循环为 `decide → validate → authorize → execute → evaluate`。
需要输入、授权或恢复处理时暂停；工具结果回到模型，模型可继续多步调用。
正文末尾的 `<task_complete/>` 表示模型提出完成，运行时按已有规则判断是否结束。

工具执行经过 `ToolRegistry.execute`，继续使用 Schema、范围和门控检查。
`agent.tools.runtime.execution_wait` 管理等待、超时和清理；结果、证据与可分页产物由
`agent.tools.runtime.result_payload`、`evidence_store` 和 `evidence_tools` 处理。
完整会话及执行记录由 `agent.core.orchestration.store` 和 SQLite checkpoint 保存。

## 其他运行模式

- 默认确定性模式：`agent.cli.pipeline → agent.collectors/工具 → agent.output`。部分收集仍直接调用工具，
  并未全部统一到注册表；统一执行入口属于后续行为调整。
- 级联扫描：`agent.scripts.full_scan` 等复用工具注册表和报告构建。
- 向外提供 MCP：`agent.server.mcp_server → agent.server.tools_bridge → ToolRegistry`。
- 接入外部 MCP：`agent.tools.adapters.mcp_tools → agent.tools.adapters.mcp_client → 外部服务器`。

## 兼容与维护约定

`agent.core.llm` 是 `agent.model.service` 的模块兼容入口。原工具顶层模块路径是新模块的轻量别名，
保留原模块对象、类和私有注入点；项目自己的运行代码使用新路径。
`agent.cli.session` 继续导出 `LazyLLM` 和 `session_prompt` 供旧调用方使用。
新代码应从 `agent.model.lazy`、`agent.core.prompts` 和对应工具子包导入。

旧 `agent.core.agent`、`agent.core.context` 和原 `system_prompt.txt` 仍用于兼容；当前交互会话主循环
位于 `agent/core/orchestration/`，默认主提示词为 `agent/core/prompt_templates/session.md`。
`agent.hallucination.evidence.EvidenceStore` 是内存登记簿，
`agent.tools.runtime.evidence_store.EvidenceStore` 是磁盘证据库，两者用途不同。

运行代码与测试分开；wheel 包含提示词模板、工具数据与 TUI 运行资源，不包含测试。
新增工具修改对应子包，通过注册表接入；新增界面复用会话工厂。

## 验证命令

在项目目录使用仓库已有虚拟环境：

```powershell
& './.venv/Scripts/python.exe' -m pytest -q
npm --prefix tui test
```

默认测试集维护冒烟与端到端测试；上游历史单元回归需显式运行 `python -m pytest -q tests/unit`。应用通过真实子进程运行，使用临时配置和本地服务，不替换业务内部组件，也不调用公网模型或目标。完整 pytest 命令包含 TUI 冒烟，要求本地 Node/TUI 依赖已安装。详见 [测试约定](testing.md)；CI 位于仓库根目录 `.github/workflows/ci.yml`。
