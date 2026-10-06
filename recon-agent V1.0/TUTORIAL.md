# recon-agent 开发教学指南 —— 跟着这个项目学会 AI Agent 开发

> 本文以 recon-agent 为教材，讲清 Agent 开发的核心概念。每个概念都对应项目里的真实文件，
> 读代码时对照路径即可。

---

## 第 0 课：Agent 到底是什么

去掉所有包装，一个 Agent 就是这样一个循环：

```
while 任务未完成:
    1. 思考（LLM 根据目标和已有观察，决定下一步）
    2. 行动（调用一个工具：执行命令 / 查 DNS / 抓 HTTP …）
    3. 观察（把工具结果塞回上下文）
```

这就是 **ReAct 模式**（Reason + Act）。LLM 本身只会"生成文本"，
让文本变成行动的，是**外层的循环代码**。对应实现：`core/agent.py::ReconAgent.run()`。

Agent 与"普通 LLM 应用"的分界线：**LLM 是否自主决定调用什么工具、传什么参数**。
在 recon-agent 里，LLM 每轮输出的是 `NormalizedToolCall`（工具名 + 参数），
代码层校验后才执行——这就是"自主性"与"安全"的分界。

---

## 第 1 课：Agent 的五大件（本项目的分层）

| 组件 | 职责 | 本项目位置 |
|---|---|---|
| 大脑（LLM 接入层） | 统一调用任意模型、归一化工具调用格式 | `model/` |
| 手（工具层） | 工具发现、Schema 校验、降级 | `tools/` |
| 记忆（上下文层） | 消息管理、Token 经济、大结果落盘 | `core/context.py`、`efficiency/` |
| 循环（编排层） | ReAct 主循环、重试、预算 | `core/agent.py` |
| 安全（守卫层） | 门控、隐蔽性、沙箱、抗幻觉 | `gate/`、`security/`、`scripts/`、`hallucination/` |

初学者最常见的错误是把所有逻辑塞进一个大文件。这个项目坚持
**单文件 ≤200 行、函数 ≤50 行**，逼着你按职责分层。

---

## 第 2 课：模型接入层——为什么必须"模型无关"

**问题**：OpenAI、Anthropic、国产模型、本地 Ollama 的 SDK 和 tool_call 格式都不同。
今天写死 OpenAI，明天换模型就要重写。

**方案**：定义自己的抽象（`model/base.py`）：

```python
class LLMProvider(ABC):
    async def complete(self, messages, tools) -> LLMResponse: ...
    def count_tokens(self, text) -> int: ...
```

唯一的 SDK 接触点是 `model/litellm_adapter.py`（LiteLLM 帮你抹平各家差异），
再把各家 tool_call 格式**归一化**成 `NormalizedToolCall(id, name, arguments)`。
业务代码只认这个结构。

三个值得学的细节：
1. **惰性导入**：litellm 没安装时，`import` 失败收敛为 `ModelUnavailable`，
   其余功能照常（离线出报告）。依赖要可降级。
2. **fallback 链**：`model/registry.py::FallbackProvider` 按配置顺序试多个模型，
   全挂才报错——生产 Agent 的标配。
3. **换模型零改码**：改 `config.yaml` 的 `model.name` 即可（HARD 验收项）。

---

## 第 3 课：工具层——Schema 是契约，不是建议

每个工具 = 一个 Pydantic 参数模型 + 一个 `run()`（`tools/base.py`）：

```python
class PortScanParams(BaseModel):
    target: str = Field(..., pattern=r"^[\w\.\-/:]+$")
    scan_type: Literal["tcp_connect"] = "tcp_connect"  # HARD: 枚举穷举
    max_rate: int = Field(1, ge=1, le=2)               # HARD: 范围写进类型
```

**要点：把约束写进 Schema（类型层），而不是写进提示词（希望层）**。
LLM 给出非法参数时 `model_validate` 直接报错，错误信息回填给 LLM 让它自己修
（校验→回填→重试闭环，`core/agent.py::_execute`）。

**渐进式披露**：工具多时不把全部 Schema 塞进上下文，
先给一行简介（`brief()`），LLM 选定再给完整 Schema——省 Token 且减少误选。

**优雅降级**：外部工具缺失时自动切内置实现（`tools/nmap_tool.py` → `tools/builtin/port_scan.py`），
但必须在结果里标注 `degraded=True` + 置信度下调 + 报告"降级清单"。
**降级不可耻，谎报能力才可耻。**

---

## 第 4 课：上下文与 Token 经济（Agent 的"内存管理"）

模型上下文又贵又有限，`core/context.py` 实现三层压缩：

```
Raw（最近消息原文） > Compaction（旧结果→文件指针） > Summarization（结构化摘要兜底）
```

四条实操规则：
1. **大输出不进 Prompt**：超 1500 token 的工具结果落盘，上下文只留摘要指针；
2. **模板化压缩**：nmap/httpx 这类固定格式输出，只把端口/状态等"变量"注入
   （`efficiency/template_compressor.py`）；
3. **调用去重**：`hash(目标+工具+参数)` 命中缓存直接复用，不重跑不重问
   （`efficiency/deduplicator.py`）；
4. **预算三档**：60% 预警（停 L2）/ 80% 收敛（只被动）/ 100% 断 LLM 出报告
   （`efficiency/budget_guard.py`）。预算耗尽的报告强制打 `[INCOMPLETE]` 水印。

---

## 第 5 课：安全 Agent 的独门功夫

这是本项目最有教学价值的部分——**LLM 的输出永远是不可信输入**。

### 5.1 Prompt 只引导，代码才兜底

提示词里写"禁止 SYN 扫描"没有强制力；`security/stealth.py::enforce_stealth`
在执行前把 `-sS` 静默剔除、把 `-sT --max-rate 1` 强制插入，并写审计日志。
**验证标准：单元测试里模拟 LLM 提出越权参数，断言代码层修正了它**
（见 `tests/adversarial/test_golden.py`）。

### 5.2 高危动作 = 人机协同（HITL）

`gate/scan_gate.py` 实现三级门控：
- L1 一次确认；L2 三次**内容不同**的独立确认（`CONFIRM 2` → 目标精确串 →
  `I UNDERSTAND AND AUTHORIZE`），通用 yes/确认 一律无效；
- 解锁生成签名文件（SHA256+时间戳+操作者指纹），**仅当次会话有效**；
- 解锁后每个动作仍需逐项确认——"解锁"≠"免确认"；
- 非交互（--batch/无 TTY）永久禁止 L2。
教训：**危险的自动化必须让"确认"贵到无法误触发。**

### 5.3 沙箱三层（`scripts/sandbox.py`）

LLM 生成的脚本执行前过三关：AST 黑名单（禁 subprocess/os/eval/写文件）→
Bandit 扫描（防 AST 被字符串拼接混淆）→ 运行时隔离（Docker 断网，缺 Docker 则
降级直跑但必须告知）。**任一层失败即拒绝**——单点校验一定会被绕过。

### 5.4 抗幻觉四道防线（`hallucination/`）

1. Schema 约束（格式）；2. 语义校验（范围）；3. **证据绑定**：每个 `ToolResult`
带 `evidence` 来源清单 + `source_hash`（响应体 SHA256），无证据的结论自动标
`[未确认，建议人工核实]`；4. **矛盾检测**：A 说 Apache、B 说 Nginx → 标
`[冲突，需人工核实]`，**禁止模型二选一**；CVE 查不到 → 硬输出"未收录"，
**禁止编造编号**；报告生成前再跑一致性校验，"报告有、证据无"的条目标 `[无证据]`。

---

## 第 6 课：可观测性——Agent 不是跑完就完了

`observability/metrics.py` 记录工具成功率、缓存命中率、Schema 错误率、
重试率、存疑数、矛盾数、隐蔽违规数（恒应为 0）等。
**重试率上升 = 模型/Prompt 回归的早期信号**；每次改提示词都要跑对抗性回归
（文档要求：通过率下降 >5% 阻断发布）。

---

## 第 7 课：跨平台的四个坑（Windows 实战）

1. **目录名遮蔽标准库**：文档规定目录叫 `platform/`，但 Python 一看
   `import platform` 会先找到项目里的同名目录，rich/pydantic 全崩。
   本项目改名 `platforms/`。这是包命名时最隐蔽的坑。
2. **路径**：一律 `pathlib.Path`，平台差异收敛到 `platforms/paths.py`
   （Windows 用 `%APPDATA%`，Linux 用 `~/.config`）。
3. **子进程**：一律 `asyncio.create_subprocess_exec`，禁 `shell=True`
   （`platforms/subprocess.py`）——既跨平台又防注入。
4. **工具发现**：Windows 要试 `.exe/.bat/.cmd/.ps1`（`platforms/tools.py`）。

---

## 第 8 课：怎么动手扩展（练习清单）

1. **加一个工具**：仿照 `tools/builtin/fingerprint.py` 写 `ssl_cert.py`
   （socket 读证书 SAN，L0 被动）——体验 Schema + 降级 + 证据绑定。
2. **加一条对抗性 golden task**：诱导 LLM "把间隔改成 0 秒"，断言
   `enforce_stealth`/`StealthRateLimiter` 拦截。
3. **接一个真模型**：`set DEEPSEEK_API_KEY=...` 后 `--session`，观察 ReAct
   循环、门控交互与 Token 指标。
4. **读源码顺序**：`core/agent.py`（循环）→ `tools/registry.py`（守卫链）→
   `gate/scan_gate.py`（门控）→ `core/context.py`（Token 经济）→ `model/`。

---

## 附：一句话总纲

> **LLM 输出不可信 → 代码层校验兜底；危险动作 → 门控+人确认；结论 → 证据绑定；
> 资源 → 预算与缓存；失败 → 显式降级不崩溃；一切 → 审计留痕。**
