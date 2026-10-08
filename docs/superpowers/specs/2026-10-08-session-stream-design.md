# 会话 CLI 流式回复与进度设计

用户要求 Claude/Codex CLI 类似的真实流式输出和加载态，并选择“逐行对话 + 流式回复 + 底部加载态”。保持现有启动方式与持久会话，用现有 Rich 实现终端呈现。

## 用户可见行为

- 提交或继续任务后立即出现等待模型的旋转加载态和耗时。首段返回后增量显示回复；工具调用显示名称、执行中、成功/失败与耗时；暂停或结束时移除加载态并恢复输入。
- 普通回复，以及原生 finish_task.answer / ask_user.question 的文本字段可增量预览。工具 JSON 参数、推理内容和 XML 工具控制块不直接输出。预览只是模型文本，完整响应校验前不得执行工具。
- 最终状态/确认问题/答案保持可用；已经完整预览的同一文本不重复打印。终端控制字符与 Rich markup 按文字安全呈现。
- 重试、备用模型切换、断流、取消都有明确状态。断流文本标为未完成，不混入后续模型回复。Ctrl+C 保持现有退出码 130、持久恢复和释放会话锁语义。
- 非 TTY / 输出重定向使用普通文本，禁止动画和 ANSI 重绘。默认流水线和 MCP 协议行为不变；不增加依赖或全屏 UI。

## 调用链

1. LLMProvider 增加非抽象的 complete_stream(messages, tools, on_delta) 扩展，默认调用旧 complete，保持已有 provider 可用。增量事件包含内容或原生工具调用片段；complete_stream 最终仍返回统一 LLMResponse。
2. LiteLLMAdapter 请求 stream=True 和 stream_options.include_usage，异步消费真实 SDK chunks、合并交错的工具参数和 usage，再按原有 _to_response 归一化。SDK 的 stream_chunk_builder 可用于聚合；覆盖真实 chunk 形状、usage-only 尾块、多个工具索引与 JSON 参数跨块。
3. 首块之前保留重试/fallback；已有任何响应片段后中断必须暂停，不能透明重试/切模型导致混合回复或重复调用。取消关闭流，完整迭代有总超时约束。错误不包含 SDK 原文或凭据。
4. LLMService 负责预算检查和消耗登记：完整回复登记一次；已发生响应的失败/取消保守记录已知 usage 或估算 token，费用未知保持未知。Runtime 在失败/取消时也保存累计用量，不能因断流丢失已消费预算。
5. SessionRuntime 接收可选、进程内 on_event 观察回调，发出 model_start/delta/end、retry/fallback、tool_start/end、plan、pause 等事件。回调不进入 checkpoint、不参与决策；渲染错误不改变执行结果。旧无回调路径继续使用 complete。
6. 独立 cli/progress.py 负责 Rich 加载态和文本预览；cli/session.py 连接渲染器、LazyLLM 流式桥接与最终状态打印。SDK 和终端库互不进入对方层。

## 验收

假流必须在最终响应前触发多次可见 delta；完整响应里的多个工具、内容与 usage 正确。验证首块前 retry/fallback、断流暂停不执行部分工具、usage/cost 不重复、取消恢复、启动零调用、工具和计划进度、非 TTY 无重绘、危险终端字符被清理、XML/工具 JSON 不泄露到回复预览、终态不重复。用 Rich force_terminal 捕获或 PTY 检查真实加载态帧；所有自动测试/演示使用本地 fixture，不发真实 API 请求或外部扫描。

## 取舍

仅加 spinner 最快但没有真实逐段反馈；全屏 TUI 需要更换输入与屏幕管理。采用用户选定的逐行 Rich 呈现和真实 SDK 流式响应，保持现有会话 API 与配置。
