import asyncio

from cync_lan.supervisor import supervise


async def _forever():
    await asyncio.sleep(3600)


async def _boom():
    raise RuntimeError("bind failed")


async def _returns():
    return None


def _called():
    calls = []

    async def cb():
        calls.append(1)

    return calls, cb


async def test_no_tasks():
    calls, cb = _called()
    assert await supervise([], cb) is False
    assert calls == []


async def test_crash_triggers_shutdown_and_reports_failure():
    calls, cb = _called()
    other = asyncio.create_task(_forever())
    crashed = asyncio.create_task(_boom())

    async def stop():
        await cb()
        other.cancel()  # what the real stop() / signal path does

    assert await supervise([other, crashed], stop) is True
    assert calls == [1]


async def test_silent_return_counts_as_failure():
    # nCyncServer.start() swallows exceptions and returns; must not be ignored
    calls, cb = _called()
    other = asyncio.create_task(_forever())
    quick = asyncio.create_task(_returns())

    async def stop():
        await cb()
        other.cancel()

    assert await supervise([other, quick], stop) is True


async def test_cancellation_is_clean_shutdown():
    calls, cb = _called()
    t1, t2 = asyncio.create_task(_forever()), asyncio.create_task(_forever())
    sup = asyncio.create_task(supervise([t1, t2], cb))
    await asyncio.sleep(0)
    t1.cancel()
    t2.cancel()
    assert await sup is False
    assert calls == []
