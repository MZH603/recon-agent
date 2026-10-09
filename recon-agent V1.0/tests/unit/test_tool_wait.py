"""Offline execution deadlines and bounded raw-result recovery."""
import asyncio
import json
from types import SimpleNamespace

from tests.unit.test_session_graph import FakeTool, Params
from tools.base import ToolResult
from tools.registry import ToolRegistry
from tools.runtime.execution_wait import ToolWaiter
from gate.scan_gate import ScanGate
from model.base import NormalizedToolCall
from utils.config import Settings


def test_pending_is_running_until_deadline_and_timeout_is_explicit(tmp_path):
    async def scenario():
        class Slow(FakeTool):
            async def run(self, params):
                await asyncio.sleep(10)
                return self.result
        settings = Settings(TOOL_TIMEOUT_SECONDS=.05, TOOL_CLEANUP_SECONDS=.03)
        registry = ToolRegistry(settings, ScanGate('example.com', auth_dir=tmp_path), 'example.com')
        registry.register(Slow())
        events = []
        task = asyncio.create_task(registry.execute(NormalizedToolCall(id='slow',name='fixture',arguments={'target':'example.com'}), on_progress=events.append))
        await asyncio.sleep(.02)
        assert not task.done() and events[0]['status'] == 'running'
        result = await task
        assert result.status == 'timeout' and result.error_code == 'TOOL_TIMEOUT'
        assert result.timeout_seconds == .05 and not result.success
        class ReturnedFailure(FakeTool):
            async def run(self, params):
                return ToolResult.err(self.name,'connection timeout while checking tcp/443')
        registry.register(ReturnedFailure())
        result = await registry.execute(NormalizedToolCall(id='returned',name='fixture',arguments={'target':'example.com'}))
        assert result.status == 'failure' and result.error_code != 'TOOL_TIMEOUT'
        await registry.aclose()
    asyncio.run(scenario())


def test_cancel_resistant_tool_does_not_extend_deadline(tmp_path):
    async def scenario():
        release = asyncio.Event()
        class Stubborn(FakeTool):
            async def run(self, params):
                try:
                    await asyncio.sleep(10)
                except asyncio.CancelledError:
                    await release.wait()
                return self.result
        settings = Settings(TOOL_TIMEOUT_SECONDS=.02, TOOL_CLEANUP_SECONDS=.02)
        registry = ToolRegistry(settings, ScanGate('example.com', auth_dir=tmp_path), 'example.com')
        registry.register(Stubborn())
        result = await asyncio.wait_for(registry.execute(NormalizedToolCall(id='x',name='fixture',arguments={'target':'example.com'})), .5)
        assert result.outcome_unknown and result.cancellation_status == 'pending'
        release.set()
        await asyncio.sleep(.02)
        assert result.status == 'timeout'
        await registry.aclose()
    asyncio.run(scenario())


def test_large_result_is_saved_and_read_in_pages(tmp_path):
    from tools.result_payload import ResultPayloads
    from tools.evidence_tools import ArtifactReadTool
    settings = Settings(TOOL_EVIDENCE_DIR=str(tmp_path), TOOL_RESULT_MAX_BYTES=1024)
    result = ToolResult(name='fixture', success=True, data={'text':'中文'*5000}, evidence=['fixture://source']).model_dump()
    payloads = ResultPayloads(settings)
    full = payloads.prepare(result, 'example.com')
    brief = payloads.for_model(full)
    from tools.evidence_store import canonical_json
    assert len(canonical_json(brief)) <= 1024
    artifact = full['artifacts'][0]
    saved = json.loads((tmp_path/'artifacts'/f"{artifact['id']}.json").read_text(encoding='utf-8'))
    assert saved['result']['data'] == result['data']
    tool = ArtifactReadTool(settings)
    async def read():
        first = await tool.run(tool.params_model(target='example.com',artifact_id=artifact['id'],offset=0,max_bytes=256))
        second = await tool.run(tool.params_model(target='example.com',artifact_id=artifact['id'],offset=first.data['next_offset'],max_bytes=256))
        assert first.success and first.data['has_more'] and second.data['offset'] > 0
        bad = await tool.run(tool.params_model(target='other.com',artifact_id=artifact['id']))
        assert not bad.success
    asyncio.run(read())

    async def public_reader():
        registry = ToolRegistry(settings,ScanGate('example.com',auth_dir=tmp_path), 'example.com')
        registry.register(tool)
        page = await registry.execute(NormalizedToolCall(id='page',name='artifact_read',arguments={
            'target':'example.com','artifact_id':artifact['id'],'max_bytes':8000}))
        view = payloads.for_model(page.model_dump())
        assert view['data']['content'] and view['data']['next_offset'] > 0
        assert len(canonical_json(view)) <= 1024
        await registry.aclose()
    asyncio.run(public_reader())


def test_blocking_function_runs_outside_event_loop_and_is_killable():
    import time
    from platforms.sync_worker import run_sync
    async def scenario():
        task=asyncio.create_task(run_sync(time.sleep,10))
        await asyncio.sleep(.05)
        assert not task.done()
        task.cancel()
        started=time.monotonic()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert time.monotonic()-started<5
    asyncio.run(scenario())


def test_remote_trait_keeps_unknown_outcome_when_only_local_wait_stopped():
    class RemoteTool:
        name = 'provider_search'
        remote_execution = True
        async def run(self, params):
            await asyncio.Event().wait()
    async def scenario():
        waiter = ToolWaiter(Settings(TOOL_TIMEOUT_SECONDS=0.02))
        result = await waiter.run(RemoteTool(), SimpleNamespace(target='example.com'), 'remote')
        assert result.status == 'timeout' and result.outcome_unknown
        await waiter.close()
    asyncio.run(scenario())


def test_remote_self_timeout_also_marks_unknown_outcome():
    class RemoteTool:
        name = 'provider_search'
        remote_execution = True
        async def run(self, params):
            return ToolResult(name=self.name, success=False, exit_code=124, error='provider timeout')
    async def scenario():
        waiter = ToolWaiter(Settings())
        result = await waiter.run(RemoteTool(), SimpleNamespace(target='example.com'), 'remote')
        assert result.status == 'timeout' and result.outcome_unknown
        await waiter.close()
    asyncio.run(scenario())
