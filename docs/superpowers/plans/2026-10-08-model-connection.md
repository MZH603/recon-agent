# Model Connection Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Goal:** Configure model name, API base and direct or environment Key together, preserving existing endpoints and fallback isolation.

**Architecture:** Extend ModelConfig and ModelSpec; resolve independent connection settings; pass SecretStr Key to existing LiteLLMAdapter only at request construction. No orchestration changes.

**Tech Stack:** Python, Pydantic SecretStr, YAML, LiteLLM, pytest.

## Task 1: Connection configuration

Files: utils/config.py, model/registry.py, model/litellm_adapter.py; tests/unit/test_model_connection.py; config.yaml; README and scoped usage/architecture documentation.

- [x] Write RED tests for YAML loading and fake SDK requests, direct/environment priority and missing environment behavior, legacy and direct custom endpoints, override/default connection, fallback isolation, masked model/spec/endpoint summaries.
- [x] Add fields and secret handling, integrate resolver and adapter. Preserve legacy constructor positional arguments and SDK ambient credential fallback when no credential is specified.
- [x] Update editable configuration examples/docs with API root and direct Key plus optional environment variable, OpenAI-compatible model prefix, fallback isolation and reload by restarting session.
- [x] Run focused GREEN and full offline regression: python -m pytest --ignore=tests/unit/test_nmap_fallback.py -k 'not golden_08' -q. No real API/scan calls. Self-review and commit explicit implementation/docs files.

## Task 2: Review and integration

- [x] Independent spec then quality review; correct material issues with regression tests.
- [x] Integrate into original main, run original-workspace regression and idle startup smoke. Mark steps and validation record; no publication.

## Verification record

- Implementation `814f7c7`: expected RED failures confirmed, then 227 passed / 1 deselected in full offline regression.
- Independent design/spec/quality review passed; focused independent model/connection/cost suite: 39 passed.
- Fast-forwarded into original main. Original-workspace final regression: 227 passed / 1 deselected in 21.29s. Default YAML connection fields loaded correctly and installed console idle/status/quit smoke passed with zero model/tool actions. No real API requests or external scans.
## Task 3: Environment-only connection selection

- [x] Write RED fake-SDK tests for RECON_MODEL/API_BASE/API_KEY overrides, single-variable credential preservation, CLI priority, named endpoint selection, blank/absent values and fallback isolation.
- [x] Implement only primary ModelSpec overlays without mutating Settings or exposing credentials. Keep YAML/old environment behavior compatible.
- [x] Document exact PowerShell startup commands and precedence; run focused GREEN/full offline regression and independent review.
- [ ] Integrate original main and verify installed idle session plus final offline regression. No real API/scan requests.

- Environment implementation 193c5c4: RED 8 failed / 7 passed, focused GREEN 38 passed, full offline regression 242 passed / 1 deselected.
- Test isolation 6337f38: dummy ambient RECON variables reproduced 18 failed / 12 passed before shared cleanup; focused model tests then passed 45 / 45. No real API or scan requests.
- Independent spec and quality review passed. Focused environment/connection/model/session-cost suite with dummy ambient variables: 54 passed in 2.78s.
