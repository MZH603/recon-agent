# 测试约定

本项目只维护端到端测试（E2E）和冒烟测试，不维护单元或集成测试，也不设置代码覆盖率门槛。

## 目录与范围

- `tests/smoke/`：真实 CLI 子进程的 help/version/工具目录、启动参数拒绝和 MCP 授权范围要求；真实 TUI 页面进程的启动、认证握手、渲染与正常退出。
- `tests/e2e/`：CLI 会话创建、三格式报告、新进程恢复；MCP 的 stdio 握手、工具列表、策略查询、范围/L1/L2 拦截，以及本地 HTTP 指纹采集与证据/审计落盘。
- `tests/conftest.py`：子进程启动与临时环境隔离，不导入或替换业务内部实现。

新增测试必须从公开程序入口或协议开始，断言退出码、用户可见输出、协议响应或真实落盘产物。禁止直接调用业务内部函数、mock/monkeypatch 业务组件，或将原单元/集成测试改名为 E2E。维护关键流程即可，不逐函数补测试。

默认用例不调用真实模型或公网目标。仅本地 HTTP/TCP fixture 提供外部服务边界，应用本身运行真实代码。模型配置、审计、SQLite、缓存、证据和报告全部放在 pytest 临时目录；不继承操作者的模型 Key、代理或本机配置。每个子进程设超时，本地服务在结束时关闭。

## 运行

从 `recon-agent V1.0/` 执行，先安装 Python 开发依赖、Node.js ≥22.19.0 和 TUI 依赖：

```text
python -m pip install -e ".[dev]"
npm ci --ignore-scripts --prefix cli/tui
python -m pytest -q              # 全部冒烟 + E2E（含 TUI）
python -m pytest -m smoke -q     # 仅冒烟
python -m pytest -m e2e -q       # 仅 E2E
npm --prefix cli/tui test        # 仅 TUI 进程冒烟
```

已有仓库虚拟环境时，Windows 可将 `python` 替换为 `& '../.venv/Scripts/python.exe'`。pytest 使用严格 marker 配置，默认只发现 `tests/smoke/` 和 `tests/e2e/`。

仓库根目录 `.github/workflows/ci.yml` 在 Windows/Linux 上执行相同完整命令。缺少 Node 或 TUI 依赖时测试明确失败，不通过 skip 隐藏安装问题。终端按键操作、全流程 TUI 会话和真实模型/公网扫描不在当前自动测试范围；发布前可按实际配置手动冒烟，结果单独记录。
