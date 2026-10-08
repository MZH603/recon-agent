"""An isolated Pi child for authentication setup, before any session runtime."""
from __future__ import annotations

import asyncio
import shutil

from cli.launcher import validate_setup
from cli.pi_bridge import PI_DIR, PiBridge, child_environment, pi_available
from cli.pi_session import close_child


async def serve_setup(bridge, defaults, settings):
    await bridge.send({'type': 'defaults', **defaults.public()})
    while True:
        command = await bridge.receive_setup()
        if command['type'] in ('quit', 'cancel'):
            code = 130 if command['type'] == 'cancel' else 0
            await bridge.send({'type': 'shutdown', 'code': code})
            return None, code
        result, errors = validate_setup(command, defaults, settings)
        # Do not retain the raw command or secret across frontend responses.
        command.clear()
        if result is not None:
            await bridge.send({'type': 'accepted'})
            return result, 0
        await bridge.send({'type': 'errors', 'errors': errors})


async def run_pi_setup(defaults, settings):
    from utils.logger import err
    available, reason = pi_available()
    if not available:
        err('Pi 界面不可用: ' + reason)
        return None, 2
    child = None
    tasks = []
    try:
        async with PiBridge() as bridge:
            child = await asyncio.create_subprocess_exec(shutil.which('node'), str(PI_DIR / 'setup-app.mjs'),
                env=child_environment(bridge.port, bridge.token))
            exited = asyncio.create_task(child.wait())
            connected = asyncio.create_task(bridge.wait_connected())
            tasks.extend([exited, connected])
            done, _ = await asyncio.wait({exited, connected}, return_when=asyncio.FIRST_COMPLETED)
            if exited in done:
                return None, 130 if exited.result() == 130 else 2
            await connected
            setup = asyncio.create_task(serve_setup(bridge, defaults, settings))
            lost = asyncio.create_task(bridge.disconnected.wait())
            tasks.extend([setup, lost])
            done, _ = await asyncio.wait({setup, exited, lost}, return_when=asyncio.FIRST_COMPLETED)
            if setup in done:
                outcome = await setup
                if outcome[0] is not None:
                    async def final_command():
                        try:
                            return await bridge.receive_setup()
                        except (EOFError, ConnectionResetError):
                            return None
                        finally:
                            # Complete the TCP half-close so Node can restore and exit.
                            bridge.writer.close()
                    final = asyncio.create_task(final_command())
                    tasks.append(final)
                    await close_child(child)
                    command = await asyncio.wait_for(final, 0.5)
                    if command is not None:
                        if command['type'] in ('quit', 'cancel'):
                            return None, 130 if command['type'] == 'cancel' else 0
                        return None, 2
                    if child.returncode != 0:
                        return None, 130 if child.returncode == 130 else 2
                return outcome
            return None, 130 if exited in done and exited.result() == 130 else 2
    except asyncio.CancelledError:
        raise
    except KeyboardInterrupt:
        return None, 130
    except (ConnectionError, EOFError, OSError, ValueError, asyncio.TimeoutError):
        err('启动配置页已断开，请检查本地 Node/Pi 安装后重试。')
        return None, 2
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if child:
            await close_child(child)
