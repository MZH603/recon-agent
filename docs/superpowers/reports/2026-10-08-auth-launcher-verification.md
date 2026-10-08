# 启动配置页最终验证

验证日期：2026-10-08。最终功能提交：`e5f434f5614bf352c43ac869634e28ebb32d67cc`，已 fast-forward 合回原项目 main。用户已确认 API Key 仅本次进程使用。

## 行为

交互终端裸启动 `recon-agent.exe` 打开 Pi 配置页，填写 API 根地址、模型、遮罩 Key、目标，并重新勾选目标授权。确认后关闭配置前端，进入现有 LangGraph L0 等待任务会话。保存的 `launcher.json` 仅含 api_base、model、target，Key 不持久化。已有参数命令保持兼容；`--auth --ui rich` 提供显式兼容入口。

## 审查与修正

- 独立设计及计划审查 Approved。
- 独立规格审查在 `6cb4050` PASS：IDNA 后保护域名校验，以及完整 CIDR 范围的保护地址重叠检查已修正；规范化后的目标用于保存和会话。
- 独立质量审查在 `e5f434f` Approved：修正 Tab/Shift+Tab/Enter 切换时误用下一字段长度上限截断上一字段。六个真实 Pi Input 回归覆盖较长 API 地址和 Key，修正前观察到五项失败。

## 最终原目录验证

在原项目目录使用根 `.venv`，隔离 APPDATA，未重新指向 editable 安装。

| 验证 | 结果 |
| --- | --- |
| Python 离线回归：`python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q` | 379 passed，1 deselected，170.19 秒 |
| 原目录 `npm.cmd test` | 16 passed |
| 本地 wheel 构建（no-deps / no-build-isolation） | 成功；确认包含最新导航修正 |
| wheel 的 Pi 资产白名单 | 精确七项生产资产；不含测试、fixture、node_modules |
| 原安装 `recon-agent.exe` 裸启动，Windows ConPTY | 配置页可输入；测试 Key 仅星号呈现；授权提交后 idle / L0 / tokens 0 |
| 会话 `status`、`quit` | idle / L0 / tokens 0；quit 退出码 0，恢复终端 |
| 原 exe 配置页 Ctrl+C | 退出码 130，恢复终端；未创建配置目录 |
| 虚构 Key 文件检查 | 配置、审计、SQLite 等该次会话全部文件均未含虚构 Key |
| 保存字段与子进程检查 | launcher 仅三个非敏感字段；拥有的 Pi Node 子进程数量 0 |
| `git diff --check` | 通过 |

Python 有一项现有 Pydantic TypedDict ReadOnly 提示。延续已有离线验证范围，外部 nmap fallback 测试及 golden_08 未执行。终端验证使用 fixture 模型、本地不可用 API 端口和虚构 Key，没有请求真实供应商 API 或执行目标扫描；真实 DeepSeek 连通性不在本次验证结论中。

验证产生的 build 目录已按已核实的绝对路径清理。拥有的 auth-launcher 工作区与已合并功能分支已移除，保留 main 原项目。

## 启动

```powershell
cd "D:\python excise\recon-agent\recon-agent V1.0"
& "..\.venv\Scripts\recon-agent.exe"
```

Tab / Shift+Tab 切换字段；Enter 从文本字段移到下一项；Space 或 Enter 勾选授权，再 Tab 到进入会话并 Enter。Esc 退出，Ctrl+C 取消。模型可填写 `deepseek-flash`，API 根地址可填写 `https://api.deepseek.com`；这仅是配置输入说明，不代表已验证远程连通性。
