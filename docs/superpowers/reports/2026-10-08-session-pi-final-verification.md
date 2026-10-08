# Pi 前端最终集成验证

运行时代码提交：b40324143c75108311bb178850efa9697eff2e3c。已快进合并到原项目 main；Python 执行、LangGraph、SQLite 和既有 RECON_* 配置保留，Pi 仅负责终端界面。

## 审查与最终回归

- 原流式后端 spec/quality 通过；Pi 初次与质量修复的 spec/quality 均通过。
- 最终规格独立验证：53 Python tests、6 Node tests；最终质量独立验证：14 Python tests、6 Node tests。
- 原目录最终离线回归：309 passed、1 deselected，43.23s。命令为 `python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q`。
- 原目录 `cli/pi` 的 `npm.cmd test`：6 passed、0 failed。
- 原目录执行 `npm.cmd ci --ignore-scripts --no-audit --no-fund`，只安装固定的 3 个本地依赖，无全局配置修改。三个 lock integrity 均与 npm 官方注册表一致。
- 父任务独立离线 wheel 构建成功：117 entries，三个生产 .mjs 和 package/lock 共 5 项资源齐全，不包含 node_modules、测试或 fixture。

## Windows 真实伪终端

执行器实证 stdin/stdout 都为 TTY，platform 为 win32。使用隔离 APPDATA，TERM=xterm-256color，未调用模型或执行扫描。

1. 工作树 `python -m cli.main --session --ui pi` 启动真实 ProcessTerminal；输入中文 `状态` 返回 idle、L0、tokens 0；`quit` 退出码 0。
2. 独立会话接收原始 Ctrl+C 字节，退出码 130。
3. 原目录已安装 `..\.venv\Scripts\recon-agent.exe --session -t example.com --authorized`，不指定 --ui，自动进入真实 Pi；status/quit 成功，退出码 0。

输出包含 Pi 的 bracketed paste / keyboard protocol 启用序列及匹配停用序列、show-cursor。上述会话退出后，本工作树的 app.mjs Node 进程数为 0。未测试物理键盘 IME；模型增量和工具反馈则由真实 Node/Pi + FakeTerminal + TCP + LangGraph fixture 验证。

原目录非 TTY 已安装入口 status/report/quit smoke 同样退出 0，无 ANSI 动画；状态为 idle、决策 0、动作 0、tokens 0，实际生成 JSON 报告，配置与报告均在独立临时目录。

## 修复与边界

已验证：完整流结束标记才允许工具执行、取消用量持久化、门控 prompt/permit 恢复、工具子进程 kill/drain/reap、坏认证/字段/深度/Unicode 帧拒绝、长回复和计划完整分段、忙时加载态与草稿保留、意外断开退出 2 并在终端关闭后提供恢复命令。

无真实模型 API 调用或外部扫描。既有外部环境 nmap fallback 和 golden_08 沿用离线排除。真实 POSIX 挂起前端仅以模拟进程验证强杀契约。过滤器仍有 P3 边缘：最终以 `x < a` 等保留标签模糊前缀结尾时，短尾可能暂存；质量审查判定不阻塞本次集成。

临时 Git worktree 登记和分支已删除，只有原项目 main。Windows 仍占用临时工作树的空目录，递归核查文件数为 0；没有未保存源码或依赖留在该目录。原项目的 node_modules 已本地安装并按 .gitignore 忽略。
