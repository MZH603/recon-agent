# recon-agent V1.0

**红队渗透测试 · 信息搜集（Recon）阶段 AI Agent**（授权测试专用）。被动优先 / 三级门控 / 代码层兜底 / 跨平台 / 模型无关 / **MCP 接入（供 Claude、ZCode 等第三方 Agent 自主调用）**。覆盖资产测绘、子域枚举与递归拓线、Web 指纹（中间件/框架/CMS）、受控端口与路径探测——**级联扫描（请求高级别自动包含全部低等级）**，输出红队视角的结构化报告。

> ⚠️ 仅用于已获合法书面授权的安全测试。默认 L0 纯被动，绝不触碰目标；任何主动探测都需确认门控。

**文档**：[项目说明书](docs/项目说明书.md)（架构/模块/安全设计） · [使用说明书](docs/使用说明书.md)（安装/参数/MCP 接入/FAQ） · [开发教学指南](TUTORIAL.md)

## 快速开始

```bash
# 1) 安装（Windows 用 .venv\Scripts；Linux 用 .venv/bin）
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"
.venv/Scripts/pip install litellm          # 仅 LLM 会话/MCP 需要；缺它仍可离线出报告

# 2) L0 纯被动采集（默认，自动执行）
recon-agent -t example.com --authorized --batch

# 3) 会话模式（配置 API Key 后，LLM 编排工具；模型不可达自动降级离线报告）
set DEEPSEEK_API_KEY=sk-...
recon-agent -t example.com --authorized --session

# 4) 主动探测（L1 一次确认；L2 三次独立确认+签名+逐项确认）
recon-agent -t example.com --authorized --profile stealth

# 5) MCP 服务器：让 Claude Desktop / ZCode 等 Agent 自主接入调用
recon-agent-mcp --authorized-for example.com --allow-l1
```

## 架构一层图

```
 ┌────────────────── 接入层 ──────────────────┐
 │ CLI (typer)           MCP stdio 服务器     │
 │ recon-agent …         recon-agent-mcp …   │
 └───────────────────┬────────────────────────┘
                     ▼
   Agent Loop（ReAct，≤5步切规划）─ LLM 决策 → NormalizedToolCall
                     ▼
   ToolRegistry 五道守卫：Schema → 合规 → 范围 → 门控 → 隐蔽修正（代码层，不可绕过）
                     ▼
   工具层（外部工具→内置降级）· 上下文/预算/去重 · 模型层（litellm fallback 链）
                     ▼
   报告（MD+JSON+CSV，水印）· 指标 · 审计日志
```

## 三级扫描深度

| 级别 | 手段 | 门控 |
|---|---|---|
| L0（默认） | DNS/CT/WHOIS/Header 指纹（纯被动） | 自动 |
| L1 | 限速 TCP Connect、banner | 一次确认（MCP 需 `--allow-l1`） |
| L2 | 版本识别/目录枚举/沙箱脚本 | 三次独立确认 + 签名文件 + 每步确认（非交互永久禁止） |

## 测试

```bash
.venv/Scripts/python -m pytest tests -q    # 126 项：单元/对抗性/跨平台/CLI/MCP/Fixture/兼容矩阵 全部通过
```


- 完整差异与设计说明见[项目说明书 §11](docs/项目说明书.md)。
