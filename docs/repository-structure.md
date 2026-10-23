# 仓库结构迁移

## 目标与边界

将原 `recon-agent V1.0/` 内的项目提升到仓库根目录。保留顶层 Python 包名、CLI 入口、工具协议和业务行为；本次不迁入 `src/recon_agent/`，不调整 Agent 循环。

## 迁移映射

| 原位置 | 新位置 |
| --- | --- |
| 版本目录中的 Python 包、tests、scripts | 仓库根目录同名位置 |
| 版本目录中的 pyproject.toml、config.yaml、Dockerfile.sandbox、system_prompt.txt | 仓库根目录 |
| 两份 README | 根目录 README.md |
| 两份 .gitignore | 根目录 .gitignore |
| 版本目录中的正式文档 | docs/ |
| 原根目录 docs 中的本地参考资料 | .local/reference-docs/ |
| 原项目 docs 中的本地计划与预览 | .local/project-notes/ 与 .local/project-tui-layout-preview.html |
| 原项目残留缓存、报告与旧元数据 | .local/legacy-project/ |

正式文档文件名改为英文 kebab-case，中文正文保留。版本目录下的已安装 TUI 依赖随 cli 目录一起迁移；Python 可编辑安装需要重新安装以更新绝对路径。

## 执行与验收

1. 核对工作区和目标路径，保留本地参考资料。
2. 提升项目目录，合并忽略规则，统一文档命名。
3. 更新 CI 工作目录、文档链接、安装和测试命令。
4. 补充贡献规范与文档索引。
5. 重新安装项目，构建 wheel，验证 CLI 和现有冒烟/E2E；扫描旧路径及断链。

GitHub Actions 原本已位于根目录；本次移除其指向旧版本目录的 working-directory。

## 验证记录（2026-10-23）

- Windows 根目录可编辑安装通过；使用已有环境，未启用构建隔离。
- wheel 构建通过；TUI、提示词及工具数据资源齐全，未包含测试、本地资料或 node_modules。
- 在仓库外启动已安装 CLI 的 `--version` 通过。
- 根目录完整 pytest：17 passed，包含 TUI 冒烟与端到端测试。
- Linux 与 GitHub Actions 远端执行尚未验证；工作流保留原双平台矩阵。

## 上游 main 合并

合并 `fd9c850` 时将新增工具、技能及测试迁入根目录结构，保留第三方工具原始内容。新增 HTTP 范围限制和其他上游功能随代码合并；README 的功能说明同步保留。

原 `tests/unit/test_full_scan.py` 的删除/修改冲突按保留上游回归用例解决，连同另外三个新增测试置于 `tests/unit/`。默认测试入口不变，可显式运行这些历史用例。

`tools/data/nuclei-readonly-status.yaml` 与 `tools/data/skills/NOTICE.md` 仍被现有文档引用，保留示例和来源说明。第三方文件保留上游格式；项目自有代码通过差异空白检查。

合并后验证：`python -m pytest -q tests/smoke tests/e2e tests/unit` 全部 33 项通过；wheel 构建通过且未包含第三方工具目录，文档本地链接无断链。首次 TUI 测试超时，单独重跑及随后完整重跑均通过。
