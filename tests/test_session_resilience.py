"""One bad packet must not drop the device connection (PLAN.md: receive_task closes on any exception)."""


import asyncio

import pytest

from cync_lan.devices.session import MAX_CONSECUTIVE_BAD_PACKETS, CyncTCPSession
from cync_lan.packet.framer import PacketFramer

PING = bytes.fromhex("d3 00 00 00 00")


def make_session(parse):
    s = CyncTCPSession.__new__(CyncTCPSession)
    s.framer = PacketFramer()
    s.bad_packets = 0
    s.mitm_mode = False
    s.lp = "test:"
    s.ip_address = "1.2.3.4"
    s.parse_packet = parse
    return s


async def test_failing_packet_does_not_stop_the_rest():
    seen = []

    async def parse(pkt):
        seen.append(pkt)
        if len(seen) == 1:
            raise KeyError("handler bug")

    s = make_session(parse)
    await s.parse_raw_data(PING + PING + PING)  # must not raise
    assert len(seen) == 3
    assert s.bad_packets == 0  # reset by the later good packets


async def test_connection_errors_still_propagate():
    async def parse(pkt):
        raise ConnectionResetError()

    s = make_session(parse)
    with pytest.raises(ConnectionResetError):
        await s.parse_raw_data(PING)


async def test_persistent_failures_eventually_raise():
    async def parse(pkt):
        raise ValueError("always")

    s = make_session(parse)
    with pytest.raises(ValueError):
        await s.parse_raw_data(PING * MAX_CONSECUTIVE_BAD_PACKETS)


async def test_stop_proxy_survives_cancelling_its_tasks():
    """Awaiting a cancelled task raises CancelledError; stop_proxy used to let it escape mid-teardown."""
    from cync_lan.structs import Tasks

    s = make_session(None)
    s.lp = "t:"
    s.tasks = Tasks()
    s.cloud_reader = s.cloud_writer = None
    s.mitm_bytes_to_cloud = s.mitm_bytes_from_cloud = 0
    s.tasks.proxy_task = asyncio.create_task(asyncio.sleep(60))
    s.tasks.proxy_conn_watcher = asyncio.create_task(asyncio.sleep(60))
    await asyncio.sleep(0)
    await s.stop_proxy()
    assert s.tasks.proxy_task is None and s.tasks.proxy_conn_watcher is None
