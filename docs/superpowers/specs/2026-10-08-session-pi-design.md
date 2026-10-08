# Pi 终端界面与 LangGraph 后端

用户在流式 CLI 改造过程中指定 earendil-works/pi，并明确选择“改用 pi-tui 前端，保留 LangGraph 后端”。这替换默认交互呈现路线；模型流式与后端事件设计仍沿用 session-stream-design。

## 边界

- 仅使用 @earendil-works/pi-tui 1.0.4 的主屏终端渲染、Markdown、Editor 和 Loader。Node 仅呈现和收集操作员输入，不使用 Pi agent-core/coding-agent、模型 SDK、工具或会话存储。
- Python 继续作为启动入口和唯一执行后端，拥有 LangGraph、LiteLLM、SQLite、范围校验、预算、授权确认与恢复。既有 RECON_* 变量和 --session/--resume 参数保持。
- 正常交互终端默认启用 Pi；提供 --ui rich 兼容模式。非 TTY / batch 使用既有纯文本路径，不能因此放开 L2。Pi 依赖缺失时 auto 路线明确提示并降级；显式 --ui pi 缺依赖则明确退出。

## 通信与生命周期

Python 主进程保留原终端 TTY 判定与 gate，只派生 Node 界面进程，让 Node 继承真实终端输入输出。进程间通过随机端口的 127.0.0.1 TCP JSONL 通信，用随机单次 token 验证首条握手。这样避免 Windows 额外文件描述符兼容问题，也避免将管道子进程伪装为 TTY 放开授权。

token 只通过子进程专用环境传递，不写入日志/报告；Node 环境仅保留终端和系统运行所需变量，不传入模型 API Key；连接拒绝错误 token、超长/坏帧及未经允许命令。一个运行只接纳一个前端，建立连接后关闭监听。没有常驻服务，不暴露远程 API。Node 不得设置后端 is_tty、gate、预算或工具参数。

后端事件发送 model delta、工具执行状态、计划、等待确认和最终可显示状态。原始工具 JSON/XML/reasoning 不呈现在 UI；复用已实现的预览过滤。日志通过事件显示，不能由 Python 直接扰乱 Node 屏幕；仅发送可显示状态，不发送 Settings、Key 或未经筛选的全部 checkpoint。

加载态在提交后立即出现，答案与澄清问题逐段 Markdown 呈现。完整已校验响应才决定工具执行；终态不重复答案。Editor 支持中文、多行和历史；忙时不能重复提交任务。状态/报告/stop/abort/quit 命令保留。Ctrl+C 明确取消并退出 130；断开/前端退出也取消正在执行的 graph，保存用量、释放锁并关闭子进程与通信资源。后台不能在 UI 消失后继续执行。

## 依赖与安装

本机 Node v24.14.0 满足库的 >=22.19.0。将精确依赖和 lockfile 放入 cli/pi，使用 npm ci --ignore-scripts；node_modules 忽略且不提交。Python wheel 包含入口 .mjs 和包清单，README 给出安装与选择界面命令，不做自动联网安装或全局 npm 安装。

## 验收

原流式测试保持通过。Python 本地真实 socket fixture 覆盖握手、分片/Unicode JSONL、提交/继续/状态/报告、授权流程、取消/断开持久恢复、监听/子进程清理、无权限参数注入。Node 原生测试用真实 pi-tui + fake Terminal 检查加载帧、增量 Markdown、Editor 提交/取消、去重、工具反馈、中文长行不超宽。至少一次 Python 后端 ↔ Node 前端的本地 fixture 端到端验证，启动零模型调用且旧安装入口可运行；检查打包资源。所有验证不调用真实模型 API 或外部扫描。
