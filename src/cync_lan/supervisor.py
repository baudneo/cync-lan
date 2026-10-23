import asyncio
import logging
from typing import List

from cync_lan.const import CYNC_LOG_NAME

__all__ = ["supervise"]
logger = logging.getLogger(CYNC_LOG_NAME)


async def supervise(tasks: List[asyncio.Task], on_failure) -> bool:
    """
    Wait on the long running service tasks.

    A task that finishes without being cancelled (it returned or raised) means a core
    service died. Log it, call ``on_failure`` (async, requests shutdown) so the rest of
    the stack comes down instead of limping along, and wait for the remaining tasks.
    A cancelled task is the normal shutdown path (signal handler cancels them).

    :return: True if any service ended unexpectedly.
    """
    lp = "CyncLAN:supervise:"
    if not tasks:
        return False
    failed = False
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in done:
        if task.cancelled():
            continue
        failed = True
        exc = task.exception()
        if exc is not None:
            logger.error(
                f"{lp} task {task.get_name()} crashed: {exc!r}", exc_info=exc
            )
        else:
            logger.error(f"{lp} task {task.get_name()} exited unexpectedly")
    if failed:
        await on_failure()
    # remaining tasks: wait for them to wind down, never let one exception escape
    remaining = list(pending)
    results = await asyncio.gather(*remaining, return_exceptions=True)
    for task, res in zip(remaining, results, strict=True):
        if isinstance(res, Exception):
            failed = True
            logger.error(f"{lp} task {task.get_name()} crashed: {res!r}", exc_info=res)
    return failed
