# 会话流式输出延迟修复验证

用户反馈：通过 OpenAI 协议调用 deepseek-flash，Pi 看起来等模型完成才显示回复。

## 已确认的代码问题

- XML 兼容协议的整个 tool_call 被文本过滤器隐藏，finish_task.answer / ask_user.question 在流中不可见。新增测试在修改前均失败；现在仅对这两个直接文本字段作增量预览，标签、扫描参数和思考内容仍隐藏。
- 适配器忽略 reasoning_content，导致思考阶段无法在界面明确显示，后续工具请求也丢失该协议字段。现在新增 reasoning 观察事件，加载态显示收到的字符数，不向 Pi 发送推理原文；完整字段存入 assistant 会话历史并随后续请求回传。部分流的预算统计包含已收到的思考内容。

DeepSeek 官方文档说明当前默认启用思考模式，并要求携带 tools 的后续请求回传 reasoning_content：<https://api-docs.deepseek.com/guides/thinking_mode/>。此次没有更改服务端默认思考模式。

## 验证

- 实际 LiteLLM 客户端连接本机 HTTP SSE 服务，经过 LLMService、LangGraph、PiBridge。分别覆盖普通文本、原生工具和 XML 协议。
- 服务端先发送 reasoning_content，停在同步屏障；确认 Pi 已收到思考进度且不含原文后，才允许发送首段答案。
- 服务端再次停在同步屏障；确认 Pi 收到首段文本、任务未完成、没有工具执行后，才发送后段及完成标记。
- 实际 SDK 的 usage 响应重建和第二轮请求均验证 reasoning_content 不丢失；所有 UI 事件不含测试推理原文。
- 实际 Node/Pi 组件与 Python IPC 联调：首段已经出现在终端渲染帧中，后段随后出现，断开界面取消任务且恢复持久用量。覆盖普通文本和 XML。
- 全套离线 Python 回归：320 passed，1 deselected；排除外部 nmap 相关测试，保留此前的离线验证范围。第三方 Pydantic ReadOnly 提示 1 条，无测试失败。
- Pi Node 回归：6 passed。补验 usage 的三个实际 SSE 场景：3 passed。
- git diff --check 通过。

未调用真实 DeepSeek API，也未执行外部扫描。上游未发送答案、上游或代理缓冲 SSE 时，客户端不能提前显示尚未收到的答案；当前改动修复的是本地文本预览和思考阶段协议处理。
