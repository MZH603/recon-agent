# Pi 前端集成作者验证

状态：DONE_WITH_CONCERNS（实现与离线验证完成；实际 Windows 交互终端未人工操作）。
工作目录：`D:\python excise\recon-agent\.worktrees\session-stream`，分支 `codex/session-stream`。
初始实施提交：`ff499bffbc3938622ee372f6c372eb2c4e639cbb`。后续质量修复提交 SHA 由作者交接提供；未合并主目录。

## 已实现边界

- 仅 `@earendil-works/pi-tui` 1.0.4，ESM main-screen、真实 Markdown/Editor/Loader；没有 Pi agent/model/store 层。
- Python 仍拥有原 stdin TTY 判定、LazyLLM、LangGraph、SQLite、预算及 gate。交互 stdin/stdout 终端 auto 选择 Pi；dumb/nonTTY/batch 走已有纯文本；rich 显式兼容。依赖缺失/Node 低版本/导入失败有提示。
- 随机 127.0.0.1 TCP 端口、随机一次 token、首帧认证、仅一客户端；坏 token 后监听继续。子环境 allowlist，模型凭据不传入；输入严格字段/类型白名单。
- UTF8 JSONL 64KiB 帧上限、128 项队列、同 preview id/offset 合并、2 秒 drain/flush 截止。预览按 6000 Unicode codepoint 分段，UI 按 offset key 排序合并成单一 Markdown，不以 UTF16 偏移切片。问答全文不裁切；过长选项标签明确省略号，状态总大小受限。
- 模型预览复用 progress 过滤；不发送 Settings、checkpoint、原工具参数或推理块。终态/提问去重，忙时 status 保留 loader。日志临时替换并恢复 stdout/stderr 与 logger cached Console。
- stop/abort/quit、Ctrl+C 与断连先取消并 await graph，持久用量后释放 owner。Node 正常停止恢复 terminal/Loader；异常挂起子界面在 graceful deadline 后强制 kill 并回收。既有本地工具子进程补取消/超时 kill + communicate 排空回收，避免退出后继续执行。
- wheel 精确包含三个生产 .mjs + package/lock；不包含 node_modules、Node 测试或 fixture。

## RED / GREEN 实证

初始 Python 6 条因缺 Pi 模块失败，Node 因缺 view 模块失败，再实现桥接与 UI。
后续 RED 复现：长回复尾部丢失、忙时 status 清空 loader、非 ASCII token TypeError、非字符串命令 type TypeError、deep JSON RecursionError、孤立 surrogate 认证异常、20 项 emoji 选项超帧。对应新增用例已 GREEN。
实际 harmless Python 子进程输出 1MB：取消 run_command/system_scan 未回收，system_scan 超时未回收，RED 3 失败；kill + communicate 修复后四路径 GREEN。没有运行扫描命令。
Windows Python 3.13 bridge cleanup 最小复现 server.wait_closed 等待活跃 accepted transport；先关闭 transport 再 wait_closed 解决。

初始提交完整命令（APPDATA 使用独立临时目录，PYTHONDONTWRITEBYTECODE=1 / PYTHONIOENCODING=utf-8）：

```text
python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k "not golden_08" -q
299 passed, 1 deselected in 38.94s

node --test *.test.mjs   # cwd cli/pi
4 passed, 0 failed
```

新增 Python 35 项：真实 loopback 认证/拒绝/Unicode JSONL、idle/resume、独立 L2 确认、停止/取消/断连用量与 owner、队列上界、长中文/emoji完整性、日志捕获恢复、CLI选择、实际 Node 子进程、依赖 probe、端口释放，以及四项 actual tool child 回收。
Node 4 项：真实 TCP 分片 Unicode、actual Editor 多行/历史/立即 loader、Ctrl+C 130、运行中状态/长 Markdown 渲染宽度与去重。

跨语言 fixture 使用真实 Node 进程、真实 createView/FakeTerminal、真实 TCP 与 LangGraph：首段 `首段中文😀` 先于后段到达，loader 立即显示；界面断开取消阻塞模型；无工具调用；重开同 SQLite 保留 >=24 tokens 和 recovery pending，owner 释放。

离线 `pip wheel . --no-deps --no-build-isolation` 成功：117 entries，以下资源齐全：
`cli/pi/app.mjs`, `view.mjs`, `bridge.mjs`, `package.json`, `package-lock.json`。
没有 node_modules、`.test.mjs`、fixture.mjs。生成的 build/ 已确认绝对路径在 worktree 内并删除。

`git diff --check` 无错误。自审关注：原授权入口/TTY gate 未改变，child env 仅 allowlist，生产 package-data 白名单，logger restored，模型 stream callback 同步且未持久化，取消 await 在 runtime exit 之前，库 Loader timer 关闭，输入协议无 gate/budget/tool 注入字段。

## 限制

未调用真实模型 API、未执行外部扫描。TTY/终端恢复通过真实 Pi + FakeTerminal 验证，没有人工实际 Windows 终端操作；已发出的线程 HTTP 请求无法撤回，但 graph 取消后不继续下一动作。
现有需外部环境的 nmap fallback 测试和 golden_08 延续前阶段离线排除约定。
安装依赖使用 `npm.cmd install --ignore-scripts`，锁定版本与 integrity；node_modules 保留本机并忽略，不提交。lock resolved URL 使用本机 npm 配置的 npmmirror，未改全局配置。

## 最终质量审查整改

以下均先记录 RED 再实施并验证 GREEN：

- 意外 EOF、协议错误、Node fixture 退出和慢 UI 失联返回 2；正常 quit 仍 0、Ctrl+C 仍 130。真实 Node 跨语言 fixture 改为断开错误码 2，仍保留用量与 recovery pending。runner 测试确认用户恢复提示在 child 已退出、stdout/cached Console 恢复之后输出。
- 普通 `status < 500`、代码比较与分片 `<` + ` 500` 保留全文；只有仍可能为 reserved 标签的前缀等待后续字符。普通 `<` 后继续逐个扫描标签，避免后续 reasoning 控制块泄露；原 split XML/ANSI 用例保持通过。未完成 `<tool_call` 前缀仍隐藏。
- child 先有 3 秒正常关闭窗口；超时改为不可捕获的 kill 并 reap。Fake Process 用例证明 terminate 无法退出时仍由 kill 结束；未声称在本机验证 POSIX 系统调用。
- 保存的 checkpoint.plan 在恢复首 state 和 status 投影；短计划直接呈现，长 Unicode 计划带明确未验证标签并按内容 hash 稳定 ID 分段，保持帧上限。恢复/查询保持零模型/工具调用。
- 实际 Pi Editor.handleInput(Enter) 用例复现 busy 拒绝时库先清空草稿；拒绝分支恢复完整原始多行 draft，同时 status 仍能提交。测试清理使用 finally 关闭 Loader。

最终验证：

```text
python -m pytest tests/unit/test_session_progress.py tests/unit/test_pi_session.py -q
53 passed in 6.55s

python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k "not golden_08" -q
309 passed, 1 deselected in 38.19s

node --test *.test.mjs
6 passed, 0 failed
```

最终累计新增 Python 45 项、Node 6 项。最终 diff --check 无错误；质量整改只涉及 progress 过滤、Pi 生命周期/计划呈现/草稿保留及相关测试和此报告。
