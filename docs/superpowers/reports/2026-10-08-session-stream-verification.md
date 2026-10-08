# 流式后端与 Python 兼容界面验证

实现位于 `codex/session-stream`。模型流式调用和 SessionRuntime 的进程内事件可复用于后续 pi-tui 前端；本提交保留逐行 Rich 兼容界面，不包含 Pi 入口或 JSONL 桥接。

## 契约与自查

- `LLMProvider.complete_stream` 是非抽象扩展，旧 provider 只实现 `complete` 仍可用；原 complete 调用路径和 RECON/fallback 独立连接保持。
- LiteLLM 流请求包含 usage，交错工具 index 的参数跨块合并。总超时覆盖建立与消费；取消关闭 aclose/close。首块前可重试与 fallback，首块后失败禁止自动切换。
- 成功要求选择 0 的 `finish_reason` 为 stop/tool_calls/function_call；正常 EOF、usage-only 尾块或有效 JSON 均不能代替完成标记。缺少标记、length 和 content_filter 暂停，部分工具不会执行。
- 使用真实离线 `litellm.ModelResponse(stream=True)` 验证 chunk 形状，并以 canonical final response 验证真实 `completion_cost` 能计算已知金额；无 usage 时按 UTF-8 字节保守预留 token（包括工具 Schema），费用保持未知。
- 成功计量一次；失败/取消在节点 finally 独立保存预算，重开恢复累计数。自查回归覆盖 model_end 观察回调触发取消时也不能擦掉已完成调用消耗。
- 观察事件不进入 checkpoint、不授予权限；普通观察异常不改变结果，CancelledError 传播。工具开始事件仅在现有授权检查通过后实际执行路径发出；开始观察回调取消时 finally 仍恢复门控 prompt、清除一次性 permit，工具不会调用。
- 普通内容及原生 answer/question 在 final 前显示；XML 控制块、带标签推理、终端控制字符、Rich markup 和跨块 JSON unicode 转义经过显示层处理。已完整预览终态不重复全文；长无换行文本按字符显示宽度提交历史，Live 只保留短行与加载态。非 TTY 和 dumb terminal 无动画。
- Python 3.10 AST 语法检查通过；超时实现使用 wait_for，无 asyncio.timeout 依赖。未调用真实模型 API 或外部扫描。

## TDD 证据

最初 7 个模型流契约因 complete_stream 缺失失败，8 个会话进度契约因 renderer/on_event 缺失失败。后续真实 SDK 成本、缺 usage 的中文保守估计、model_end 取消时预算以及无结束标记的有效工具 JSON 回归均先观察到失败，再修正。

## 本地命令

在 `recon-agent V1.0` 中，使用仓库根 `.venv/Scripts/python.exe`，设置 `PYTHONDONTWRITEBYTECODE=1`、`PYTHONIOENCODING=utf-8`，APPDATA 指向独立临时测试目录：

```powershell
python -m pytest tests/unit/test_model_stream.py tests/unit/test_session_progress.py tests/unit/test_session_cli.py tests/unit/test_session_graph.py tests/unit/test_session_cost.py -q
python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q
```

最终 focused：84 passed。最终全离线回归：264 passed，1 deselected。`git diff --check` 无输出。
