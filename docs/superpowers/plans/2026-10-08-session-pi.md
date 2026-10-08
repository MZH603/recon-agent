# Pi Terminal Integration Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** Default interactive --session to a real pi-tui interface while retaining the Python LangGraph backend and existing configuration.

**Architecture:** Python starts an authenticated ephemeral loopback JSONL bridge and an inherited-terminal Node child. Node owns presentation; the original Python process owns permissions, graph, model and persistence. Reuse complete_stream/events and keep Rich as an explicit/plain fallback.

**Tech Stack:** Python asyncio, Node >=22.19, pinned @earendil-works/pi-tui 1.0.4, existing Rich/LangGraph/SQLite, pytest, node:test.

## Task 1: Pi interface and backend bridge

Files under recon-agent V1.0: cli/main.py, new cli/pi_session.py and/or pi_bridge.py; cli/pi/package.json/package-lock.json plus small .mjs modules for bridge/view/app; pyproject.toml package data, README/docs/使用说明书.md, .gitignore if needed, tests/unit/test_pi_session.py and cli/pi/*.test.mjs. Existing platforms/subprocess.py and tools/system_scan.py need the narrow cancellation/reaping repair confirmed by a harmless local child fixture.

- [ ] Write RED bridge and UI tests: actual loopback framing, authenticated single connection, rejected malformed/oversized commands, no frontend permission override, idle zero calls, incremental output, interrupt/resume, cancellation/disconnect cleanup and durable usage. Real pi-tui components with fake Terminal test rendering, input, loader, long Unicode and deduplication.
- [ ] Add pinned frontend manifests and install locally with npm ci --ignore-scripts. Never commit node_modules; no global install. Read installed declarations/source for exact APIs.
- [ ] Implement authenticated one-session bridge. Keep gate is_tty from original Python CLI; frontend cannot send it. Scope command protocol to task/resume/state/report/stop/abort/quit; backend remains sole executor. Redirect runtime logs into display events, cancel and reap already-started external tool subprocesses, safely project events/state, handle backpressure/frame bounds and restore stdout/stderr after exit.
- [ ] Implement main-screen Pi transcript, incremental Markdown, multi-line Editor and bottom Loader/status. Complete native control preview, no raw tool JSON/XML/reasoning. Busy-state submission guard, existing commands, Ctrl+C cancellation/130, terminal cleanup on every exit.
- [ ] Wire --ui auto|pi|rich selection; interactive auto uses installed Pi, non-TTY/batch plain Rich, explicit Pi missing dependency errors clearly. Existing tests/fake run_session APIs remain compatible. Include .mjs/manifests in Python package assets; update installation/use docs around final implementation.
- [ ] Run focused Python/Node GREEN and full offline regression, local cross-language slow fixture, packaging asset check, self-review and explicit commit. No real API/scan.

## Task 2: Review and integration

- [ ] Independent spec then quality review of Pi layer and its integration with streaming backend; fix material issues with regression.
- [ ] Integrate original main, install frontend dependencies in original checkout, final offline Python/Node regression and installed idle/plain smoke.
- [ ] Verify a forced-terminal/fake-Terminal end-to-end fixture for incremental replies, loading/tool frames and clean input; verify frontend exit cancels backend.
- [ ] Record results, clean merged worktree, deliver exact startup command and material limits.

## Verification record

- Pi package 1.0.4 and Node engine verified against npm registry; local Node v24.14.0, npm 11.9.0.

- During integration, a harmless child that writes local start/end markers confirmed run_command cancellation left the process alive. Add kill/drain/reap on cancellation to the shared command wrapper and direct system_scan path; preserve CancelledError propagation. No change to scan permissions or commands.
