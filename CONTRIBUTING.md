# 贡献规范

## 仓库结构

仓库根目录就是 Python 项目根目录。安装、测试及 CI 均从这里运行，不创建带版本号的项目外壳目录。发布版本由 `pyproject.toml` 管理。

| 位置 | 职责 |
| --- | --- |
| `.github/workflows/` | GitHub Actions 工作流 |
| `pyproject.toml` | Python 依赖、打包、命令入口和 pytest 配置 |
| `cli/`、`cli/tui/` | Python CLI 与 Node.js 终端界面 |
| `core/` | Agent 会话、提示词与编排 |
| `model/` | 模型协议、适配和调用 |
| `tools/` | 工具契约、注册表、内置工具、适配器及运行时 |
| `collectors/`、`knowledge/` | 采集与知识处理 |
| `gate/`、`security/`、`hallucination/` | 授权、范围限制及证据一致性 |
| `efficiency/`、`observability/` | 预算、上下文、去重及指标 |
| `output/`、`server/` | 报告和 MCP 服务 |
| `platforms/`、`utils/` | 平台适配及公共设施 |
| `scripts/` | 现有扫描和沙箱脚本 |
| `tests/smoke/`、`tests/e2e/` | 公开入口的冒烟与端到端测试 |
| `tests/unit/` | 合并保留的上游历史回归测试，显式运行 |
| `skills/` | 上游提供的技能说明 |
| `docs/` | 纳入版本控制的正式文档 |
| `.local/` | 不提交的参考仓库、草稿及迁移保留资料 |

当前保留现有顶层 Python 包及导入路径。包命名空间迁移与业务重构应单独实施。

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
npm ci --ignore-scripts --prefix cli/tui
python -m pytest -q
npm --prefix cli/tui test
git diff --check
```

完整 pytest 已包含 TUI 冒烟；只修改 TUI 时可先运行 npm 测试，最终按变更范围验证。测试约束见 [测试约定](docs/testing.md)。CI 在 Linux 和 Windows 上运行安装与完整测试。

目录或打包变更还需验证 wheel 能构建、CLI 能从仓库外启动，并检查旧路径和文档链接。

## 本地文件与变更范围

不提交凭据、虚拟环境、node_modules、数据库、日志、报告或构建产物。正式文档不能通过忽略整个 `docs/` 隐藏。参考资料放在 `.local/`，不要覆盖已有本地文件。

结构迁移、业务行为变更和大规模格式化分别组织，便于审阅。提交前查看差异，避免意外纳入本地文件；描述变更原因、验证结果和未验证范围。
