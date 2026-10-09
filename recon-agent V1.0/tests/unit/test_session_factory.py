"""Shared session construction stays idle and preserves injection/resume behavior."""
import asyncio
import importlib

from model.base import LLMResponse
from utils.config import Settings


def test_shared_factory_is_idle_lazy_and_resumable(tmp_path, monkeypatch):
    from core.session_factory import create_session_runtime

    monkeypatch.setattr('platforms.paths.get_config_dir', lambda: tmp_path)
    calls = []

    class Model:
        async def complete(self, messages, tools):
            calls.append('complete')
            return LLMResponse(content='已完成。\n<task_complete/>')

    def model_factory(settings, model):
        calls.append((settings, model))
        return Model()

    settings = Settings(TOOL_EVIDENCE_DIR=str(tmp_path / 'evidence'))

    async def scenario():
        runtime = create_session_runtime(target='example.com', settings=settings,
            batch=True, is_tty=False, model_override='fixture', session_id='shared',
            llm_factory=model_factory)
        assert runtime.session_id == 'shared'
        assert runtime.registry.get('recon_note').store.session_id == 'shared'
        assert runtime.settings is settings
        assert runtime.registry.main_target == runtime.gate.target == 'example.com'
        assert runtime.db_path == tmp_path / 'agent_state.sqlite'
        assert runtime.gate.current_level() == 0
        assert calls == [] and not runtime.db_path.exists()
        async with runtime:
            assert (await runtime.state())['status'] == 'idle'
            assert calls == []
            result = await runtime.submit('回答即可')
            assert result['status'] == 'completed'
            assert calls == [(settings, 'fixture'), 'complete']
            assert runtime.llm.service.guard is runtime.llm.guard
        restored = create_session_runtime(target='example.com', settings=settings,
            batch=True, is_tty=False, resume_id='shared', session_id='ignored',
            llm_factory=model_factory)
        assert restored.session_id == 'shared' and restored.require_existing
        assert restored.registry.get('recon_note').store.session_id == 'shared'
        async with restored:
            assert (await restored.state())['status'] == 'completed'
            assert len(calls) == 2

    asyncio.run(scenario())


def test_legacy_model_module_is_the_canonical_module():
    assert importlib.import_module('core.llm') is importlib.import_module('model.service')


def test_session_prompt_keeps_override_and_dynamic_capabilities(tmp_path):
    from core.prompts import session_prompt

    class Registry:
        def briefs(self):
            return ['fixture: 本地工具']

    registry = Registry()
    settings = Settings()
    default = session_prompt(registry, 'example.com', settings)
    assert '<task_complete/>' in default and 'TOOL_TIMEOUT' in default
    assert 'example.com' in default and 'fixture: 本地工具' in default
    prompt = tmp_path / 'custom.md'
    prompt.write_text('自定义主提示词', encoding='utf-8')
    settings.SESSION_PROMPT_FILE = str(prompt)
    overridden = session_prompt(registry, 'example.net', settings)
    assert overridden.startswith('自定义主提示词\n')
    assert 'example.net' in overridden and 'fixture: 本地工具' in overridden
