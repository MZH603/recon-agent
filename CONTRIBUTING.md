# 贡献规范

## 仓库结构

仓库根目录就是 Python 项目根目录。安装、测试及 CI 均从这里运行，不创建带版本号的项目外壳目录。发布版本由 `pyproject.toml` 管理。

| 位置 | 职责 |
| --- | --- |
| `.github/workflows/` | GitHub Actions 工作流 |
| `pyproject.toml` | Python 依赖、打包、命令入口和 pytest 配置 |
| `agent/` | Python 后端包：CLI、会话编排、模型、工具、门控、MCP、采集和报告 |
| `tui/` | Node.js 终端界面与 Python 本地桥接适配 |
| `third_party/tools/` | 上游第三方工具、二进制及字典，不进入 wheel |
| `tests/smoke/`、`tests/e2e/` | 公开入口的冒烟与端到端测试 |
| `tests/unit/` | 合并保留的上游历史回归测试，显式运行 |
| `skills/` | 上游提供的技能说明 |
| `docs/` | 纳入版本控制的正式文档 |
| `.local/` | 不提交的参考仓库、草稿及迁移保留资料 |

Python 后端统一使用 `agent.*` 导入。TUI 可调用后端公开入口；后端运行逻辑不依赖 TUI 页面实现。

## 命名与文档

- Python 包、模块和函数使用 `snake_case`；类使用 `PascalCase`；常量使用 `UPPER_SNAKE_CASE`。
- 普通文档文件使用英文 `kebab-case.md`，正文可使用中文；`README.md`、`CONTRIBUTING.md` 等标准文件名保留。
- 目录名不加版本号或空格。现有工具名称、CLI 参数及兼容入口不因目录整理而变更。
- `README.md` 是唯一的安装与快速开始入口；`docs/README.md` 提供文档导航。
- 路径以仓库根目录为基准；Markdown 链接相对当前文档解析。不要写入个人机器绝对路径。
- 修改入口、路径或命令时，同步更新 CI、打包配置、脚本和相关文档。

## 开发与验证

在仓库根目录创建并激活虚拟环境，使用 Python >=3.10 和 Node.js >=22.19.0：

```sh
python -m pip install -e ".[dev]"
npm ci --ignore-scripts --prefix tui
python -m pytest -q
npm --prefix tui test
git diff --check
```

完整 pytest 已包含 TUI 冒烟；只修改 TUI 时可先运行 npm 测试，最终按变更范围验证。测试约束见 [测试约定](docs/testing.md)。CI 在 Linux 和 Windows 上运行安装与完整测试。

目录或打包变更还需验证 wheel 能构建、CLI 能从仓库外启动，并检查旧路径和文档链接。

## 本地文件与变更范围

不提交凭据、虚拟环境、node_modules、数据库、日志、报告或构建产物。正式文档不能通过忽略整个 `docs/` 隐藏。参考资料放在 `.local/`，不要覆盖已有本地文件。

结构迁移、业务行为变更和大规模格式化分别组织，便于审阅。提交前查看差异，避免意外纳入本地文件；描述变更原因、验证结果和未验证范围。
