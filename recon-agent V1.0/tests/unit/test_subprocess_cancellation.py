"""Cancellation must reap actual harmless local children, including full pipes."""
import asyncio
import sys
from types import SimpleNamespace
import pytest


@pytest.mark.parametrize('route',['command','system_scan'])
@pytest.mark.parametrize('ending',['cancel','timeout'])
def test_cancellation_and_timeout_reap_child_with_large_pipe(tmp_path,monkeypatch,route,ending):
    from platforms.subprocess import run_command
    from tools.system_scan import SystemScanTool,SystemScanParams
    from utils.config import Settings
    started=tmp_path/'started';ended=tmp_path/'ended'
    code="import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text('started');sys.stdout.write('x'*1000000);sys.stdout.flush();time.sleep(.8);pathlib.Path(sys.argv[2]).write_text('ended')"
    args=[sys.executable,'-c',code,str(started),str(ended)]
    processes=[];original=asyncio.create_subprocess_exec
    async def spawn(*args,**kwargs):
        proc=await original(*args,**kwargs);processes.append(proc);return proc
    monkeypatch.setattr(asyncio,'create_subprocess_exec',spawn)
    if route=='system_scan':
        tool=SystemScanTool.__new__(SystemScanTool)
        tool._settings=Settings();tool._settings.CONNECT_TIMEOUT=.02 if ending=='timeout' else 10
        tool._available={'dig':SimpleNamespace(path=sys.executable)}
        monkeypatch.setitem(__import__('tools.system_scan',fromlist=['COMMAND_TEMPLATES']).COMMAND_TEMPLATES,'dig',args)
        operation=lambda:tool.run(SystemScanParams(tool='dig',target='example.com'))
    else:operation=lambda:run_command(args,timeout=.06 if ending=='timeout' else 10)
    async def scenario():
        task=asyncio.create_task(operation())
        if ending=='cancel':
            for _ in range(1000):
                if started.exists():break
                await asyncio.sleep(.01)
            assert started.exists()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):await asyncio.wait_for(task,2)
        else:await asyncio.wait_for(task,10)
        assert processes[0].returncode is not None,'child was not reaped'
        await asyncio.sleep(.9)
        assert not ended.exists(),'child continued work after UI cancellation'
    asyncio.run(scenario())
