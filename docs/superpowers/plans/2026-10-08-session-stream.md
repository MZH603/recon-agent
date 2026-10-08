# Session Streaming Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development. Steps use checkboxes for tracking.

**Goal:** Make --session display real streamed replies and immediate model/tool loading feedback without changing session authorization and recovery.

**Architecture:** Backward-compatible complete_stream provider extension plus ephemeral runtime progress events; a separate Rich renderer previews model content and user-facing control fields. Complete validated responses remain the only source of executable calls and durable conversation state.

**Tech Stack:** Existing Python, LiteLLM async streaming, LangGraph, SQLite checkpoints, Rich, pytest. No new dependencies.

## Task 1: Stream and progress integration

Files under recon-agent V1.0: model/base.py, model/litellm_adapter.py, model/registry.py, core/llm.py, core/orchestration/{graph,decisions,execution,support}.py as needed, cli/session.py, new cli/progress.py, focused tests/unit/test_model_stream.py and test_session_progress.py; README/docs/使用说明书.md.

- [x] Write fake-stream RED tests for incremental callbacks before final completion, content/control argument aggregation, usage-only tails, retries before chunks, no retry/fallback after partial response, safe errors, closure/total timeout, budget persistence on interruptions and cancellation. Assert real data flow rather than matching implementation.
- [x] Implement complete_stream default compatibility and LiteLLM streaming. Stream errors carry sanitized accounting data; preserve ordinary complete behavior, independent connection configs and hidden credentials.
- [x] Add LLMService/LazyLLM stream bridge with single usage accounting; optional process-only runtime progress observer. Emit tool events only around authorized real execution; never execute partial calls or cache progress as state.
- [x] Implement Rich sequential renderer and CLI wiring; loading state starts immediately, status includes elapsed time; show user-facing text/control fields safely, suppress protocol fragments and duplicate final text. Close display before operator input or on cancellation. Plain output has no ANSI animation.
- [x] Update usage docs. Run targeted GREEN plus full offline regression: python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q. Self-review and commit only implementation files.

## Task 2: Independent review and final verification

- [x] Independent spec then code quality review; resolve material findings with regressions.
- [ ] Integrate into original main and run final offline regression and installed console idle smoke.
- [ ] Capture a deterministic slow local fixture in a forced-terminal console or PTY, checking loading frames, incremental reply before final completion, tool progress, clean prompt and no duplicate text. No real API requests/scans.
- [ ] Record evidence, clean the fully integrated worktree, and report unchanged startup command and user-visible behavior.

## Verification record

- Baseline focused model/environment/session/cost tests: 43 passed in 2.84s.

- Implementation bec997c: focused 84 passed; full offline 264 passed, 1 deselected. Independent review: spec PASS, quality PASS; reviewer focused 41 passed.
- Integration, installed smoke, and cleanup are carried into session-pi.md because the user selected Pi as the default frontend before integration.
