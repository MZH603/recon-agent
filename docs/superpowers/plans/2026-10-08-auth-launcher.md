# Auth Launcher Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 裸命令打开 API/目标配置页，Key 仅本次使用，提交后进入现有等待任务会话。

**Architecture:** 配置页是现有会话之前的单独生命周期。Python 负责配置预填、校验与仅非敏感持久化，Pi 负责遮罩表单，确认结果以可选显式连接传入现有 LLM 路由。业务 CLI、授权门控、LangGraph/SQLite 不改语义。

**Tech Stack:** Python/Typer/Rich/Pydantic，现有 Pi TUI 1.0.4 与认证 TCP JSONL，无新依赖。

## Task 1: 完整启动配置纵向功能

此任务包含紧密依赖的表单、桥接和入口，交给一个实现者顺序完成，避免多个实现者同时改动生命周期。遵循 @test-driven-development；每部分先写行为测试、运行观察失败，再最小实现。

**Create:** recon-agent V1.0/cli/launcher.py、cli/pi_setup.py、cli/pi/setup.mjs、cli/pi/setup-app.mjs、tests/unit/test_launcher.py、cli/pi/setup.test.mjs。

**Modify:** recon-agent V1.0/cli/main.py、cli/pi_bridge.py、cli/session.py、cli/pi_session.py、model/registry.py、core/llm.py、pyproject.toml、README.md、docs/使用说明书.md（依实际现有路径）。

- [x] 写并运行失败的 Python 测试：defaults/validation/store 符合 spec；save/load 只输出 api_base/model/target；repr/文件/UI 事件不含虚构 Key；显式确认值覆盖环境变量但旧 resolve_model 不变；未知 schema/授权 false 不进入会话。
- [x] 实现 launcher 的单次结果（SecretStr 保密）和预填。成功提交调用最小主连接对象；使用原子替换保存非敏感字段，不修改 YAML 或写入 api_key。校验返回固定字段错误。Rich fallback 用隐藏输入确认，失败保留页面继续编辑；不自动调用模型。
- [x] 写并运行失败的 Node 表单测试：真实输入 Tab/Shift+Tab/Enter/粘贴/删除、窄终端、Key 从未渲染/未进入历史、授权默认 false、重复提交阻止、错误反馈和清空敏感缓存。
- [x] 实现 setup.mjs/setup-app.mjs：使用 Pi 单行组件或独立 masked input，若复用 Input 不得渲染真实 Key，清空组件内部缓存应通过丢弃整个敏感组件。提交后仅向认证本地桥发送一次 configure 对象；UI 显示固定确认错误而不回显任何 Key。
- [x] 写并运行失败的实际 TCP roundtrip 与前端清理测试。增加独立 receive_setup（或等价配置桥类）：严格 type/字段/长度/布尔规则，只允许配置阶段命令；运行期 receive 仍拒绝 configure。
- [x] 实现 pi_setup 生命周期：前端连接后发送非敏感预填和已有 Key 标记；只在后端校验成功后发 accepted，关闭配置前端，返回单次 Python 结果。失败/退出/断开有期限地关闭连接、等待或终止子进程，避免配置秘密流入日志捕获。
- [x] 写并运行失败的 CLI 路由测试：CliRunner 裸参数进入 launcher 并以 L0/session 等待；doctor/version/help/mcp/既有 -t 命令不触发 launcher；--auth 可明确打开；非 TTY/--batch 立即报错不读输入。通过 Typer Context 的参数来源区分裸命令，不能依赖测试进程的 sys.argv。
- [x] 实现裸命令/--auth 入口，以及可选 connection_override 传递到 LazyLLM/LLMService/build_provider；旧路径仅 None 时不改变已有函数 monkeypatch/调用签名语义。配置页输入值是显式主连接，不再走旧环境变量覆盖；fallback 仍独立。
- [x] 更新 pyproject.toml 生产资产白名单、README/使用说明书：PowerShell 使用 &；裸命令流程；Key 仅本次、已有环境变量可预填、授权每次确认；旧命令仍有效。不要添加登录账号/云同步/真实连接测试/多 profile 等新功能。
- [x] 运行并审查：`python -m pytest tests/unit/test_launcher.py tests/unit/test_pi_session.py tests/unit/test_model_connection.py -q`、`npm.cmd test`；所有新测试通过，现有测试按改动合适修正，仅逻辑变化必要时。
- [x] 提交功能，交给独立 spec reviewer 以及其后 quality reviewer；修改审查问题并复验。


## Root Final Verification / Integration

- [x] worktree 使用根 .venv 的 python（cwd 为工作区 nested project，避免改 editable 指向）；Pi node_modules 从原项目已安装依赖复制到工作区。
- [x] 运行完整离线 Python：`python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q`，隔离 APPDATA；运行 Node 全部测试。
- [x] 本地 wheel 构建和资产 whitelist 校验；Windows ConPTY 运行 `python -m cli.main` 裸命令，输入非敏感 fixture 参数/虚构 Key/授权后进入 idle，status/quit，另测 Ctrl+C；不进行 API 调用或扫描。
- [x] 写验证报告，按已授权范围合回原项目并验证安装的 recon-agent.exe 裸命令；清理拥有的工作区。不重复请求相同方案的批准。
