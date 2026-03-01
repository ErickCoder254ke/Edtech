import asyncio
from typing import Any

_TASK_LOOP: asyncio.AbstractEventLoop | None = None


def run_async(coro: Any) -> Any:
    """Run coroutine on a persistent per-process event loop.

    Celery prefork workers execute many tasks in one process. Using asyncio.run()
    per task can close loops while Motor still references them, causing
    'RuntimeError: Event loop is closed'.
    """
    global _TASK_LOOP
    if _TASK_LOOP is None or _TASK_LOOP.is_closed():
        _TASK_LOOP = asyncio.new_event_loop()
        asyncio.set_event_loop(_TASK_LOOP)
    return _TASK_LOOP.run_until_complete(coro)

