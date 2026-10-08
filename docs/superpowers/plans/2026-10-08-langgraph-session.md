# LangGraph Session Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Replace --session with a working, resumable LangGraph agent that waits for instructions and pauses for human decisions.

**Architecture:** Stateful graph reuses existing LLM and registry. SQLite checkpointer and execution journal retain conversation, full results and uncertain actions. CLI manages interrupt replies and report commands; authorization remains process-local.

**Tech Stack:** Python, LangGraph 1.x, langgraph-checkpoint-sqlite 3.x, aiosqlite, LiteLLM, Pydantic, Typer, pytest.

---

## Task 1: Durable orchestration runtime

Files: create `recon-agent V1.0/core/orchestration/{__init__,state,store,controls,graph,support,decisions,authorization,execution,ownership}.py`, tests `tests/unit/test_session_graph.py`; modify pyproject.toml dependencies and targeted gate invariants. Work in `.worktrees/langgraph-session`.

- [x] Write behavior tests using scripted LLMResponse and fake BaseTool but real LangGraph/SQLite: empty session does nothing; tool invocation records full result; ask pauses and resumes; control finish distinguishes completion; serial multi-call handling; bounded parameter correction; failed tool pause; model outage and budget pause; scope rejection; loop limit; cache success data reuse; restart keeps messages/results/budget; uncertain started action asks before rerun; completed journal restores result. Run `python -m pytest tests/unit/test_session_graph.py -q` and confirm missing behavior fails.
- [x] Implement state TypedDict with serializable target, messages, plan, queue, results, status, answer, steps/limits, budget counters, errors and pending questions. Graph factory/runtime accepts injected registry, llm, gate, settings and DB path/session ID; expose async start/submit/resume/state methods and async context manager closing SQLite. Preserve message tool-call validity. Control tools ask_user/update_plan/finish_task have explicit schemas; plain model content treated as clarification unless evidence-backed task completion explicit. Keep XML compatibility.
- [x] Implement SQLite store/journal for unique execution ID, canonical args fingerprint, started/completed/uncertain entries, result JSON. Validate and scope-check before interrupts; serial authorization interrupt nodes obtain exact L2 codes and action yes. Use current process gate; checkpoint authorization tokens never confer permission after restart. Registry execution must still guard tools without duplicate stdin prompts: inject a prompt callback backed by graph interrupt or an internal one-shot approval route validated by current gate, never bypass compliance/schema. All resume paths including checkpoint pending execution recheck process authorization.
- [x] Persist full successful result cache per task, return successful result with cache metadata. Check cumulative budget and action/decision bounds before model/tools. Permit <=2 parameter self-corrections then ask. Failures and conflicts pause rather than blindly rerun. Leave model failure state resumable. Execution journal commits started before tool and completed before checkpoint. Recovery questions allow skip or explicit retry; completed result reused.
- [x] Run focused tests GREEN and self-review. Commit runtime and tests. Report exact APIs for CLI.

## Task 2: CLI and evidence reports

Files: replace `cli/session.py`; modify `cli/main.py`; create `output/session_report.py`; tests `tests/unit/test_session_cli.py`, `tests/unit/test_session_report.py`; README and usage/architecture docs. Repair scoped model cost accounting in `model/litellm_adapter.py` and `core/llm.py`, with adapter/service tests, so real provider costs reach persistent budgets.

- [x] Write failing CLI tests with injected input/LLM/runtime: launch/EOF has no model/tool calls; task and interrupt reply; report while paused does not resume execution; --resume requires --session and matching target; output directory and format; abort; no pipeline fallback. Write report tests with representative actual ToolResult structures for all tools and failures/degraded/conflicts/uncertain; JSON retains full records. Confirm RED.
- [x] Add --resume optional CLI arg, validate incompatible modes, pass to run_session. Keep existing non-session routes. Lazily build model on first task; run_session opens database and prints ID/resume command, then waits. New commands 状态/status, 报告/report, abort, quit/退出; pending interrupts display meaningful question and next input resumes. Reopening shows pause and revalidates auth. EOF/KeyboardInterrupt saves report when useful and closes resources without launching old pipeline.
- [x] Implement session report adapter converting real tool results into ReconData fields and preserving execution details in JSON and traceable Markdown. Report files follow selected output_dir/format; partial tasks include incomplete watermarks, degraded markers and evidence contradictions. LLM text identified as analysis and claims unsupported by tool evidence flagged. Use existing metrics/save_report conventions as practical.
- [x] Add failing cost-accounting tests using fake SDK metadata and existing adapter/service interfaces. Preserve provider response cost (or LiteLLM pricing calculation when available) in normalized response, register it in LLMService and verify no double counting in runtime. Explicitly mark unavailable cost estimates; never claim exact monetary enforcement without pricing data.
- [x] Document install, startup, ID recovery, commands, authorization, model errors and first-stage boundaries. Run focused tests and legacy offline regression. Commit.

## Task 3: Integrated verification and corrections

- [x] Run `python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q` with isolated APPDATA/no bytecode. These two legacy tests access external targets; all new tests use offline fixtures.
- [x] CLI --help and pipe commands to ensure wait/no scan and report. Real SQLite fresh-process resume smoke with local fake tools. Build/install package and smoke outside source tree so required resource packaging is checked.
- [x] Independent spec review then quality review of runtime, CLI/report and final integration; fix material findings with regression tests and rerun affected suites. Mark task checkboxes, record actual validation and limitations. Return implemented branch and usage; integrate changes into original workspace once verified, without external publication.

## Execution record

- Design and plan reviews approved. User authorized implementation through completion.
- Baseline offline regression: 133 passed, 1 deselected.
- Runtime commit `46da4ff`: 35 runtime behavior tests plus 12 legacy gate/full-scan tests passed (47 total). Spec review passed after correcting native multi-call message order, XML list parameters, durable error history and invalid uncertainty replies. Quality review passed after OS session ownership and bounded total-work accounting were added in `1880425`. Independent focused suite: 55 passed; full offline regression: 176 passed, 1 deselected. An additional 125-control-call SQLite probe preserved 126 native tool replies across bounded resumes.


- CLI/report/cost commit `344d829`: 202 passed, 1 deselected offline; independent spec review passed (26 focused tests and full regression). Installed wheel passed idle/report/resume/resource checks outside the source tree and five-process authorization/uncertainty recovery. Code quality review passed after correcting mixed DNS answer classification in `d57aac6`; report regression 8 passed, full offline 204 passed, 1 deselected. Final interaction audit passed. The final wheel was rebuilt and passed all package/CLI checks. Fast-forwarded into original main, installed editable project into root .venv, and verified the installed console entry. Original-workspace regression: 204 passed, 1 deselected in 23.12s; idle report and fresh console resume passed with zero decisions/actions.
