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
- [ ] Integrate into original main, run original-workspace regression and idle startup smoke. Mark steps and validation record; no publication.

## Verification record

- Implementation `814f7c7`: expected RED failures confirmed, then 227 passed / 1 deselected in full offline regression.
- Independent design/spec/quality review passed; focused independent model/connection/cost suite: 39 passed.
- Original workspace integration and final regression remain to be performed. No real API requests or external scans.
