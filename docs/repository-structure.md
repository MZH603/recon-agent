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
