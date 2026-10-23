import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from cync_lan.stats import Counters, stats


def test_counters_basics():
    c = Counters()
    c.inc("b")
    c.inc("a", 3)
    c.inc("zero", 0)  # untouched counters stay out of the snapshot
    snap = c.snapshot()
    assert list(snap)[:2] == ["a", "b"]
    assert snap["a"] == 3 and "zero" not in snap and "uptime_seconds" in snap
    c.reset()
    assert c.get("a") == 0


@pytest.fixture(autouse=True)
def _reset():
    stats.reset()
    yield
    stats.reset()


async def test_session_counts_dropped_bytes_and_failed_packets():
    from cync_lan.devices.session import CyncTCPSession
    from cync_lan.packet.framer import PacketFramer

    PING = bytes.fromhex("d3 00 00 00 00")

    async def parse(pkt):
        raise KeyError("x")

    s = CyncTCPSession.__new__(CyncTCPSession)
    s.framer, s.bad_packets, s.mitm_mode = PacketFramer(), 0, False
    s.lp, s.ip_address, s.parse_packet = "t:", "1.2.3.4", parse
    await s.parse_raw_data(b"\x01\x02" + PING + PING)  # two junk bytes, two packets, both fail
    assert stats.get("framer_dropped_bytes") == 2
    assert stats.get("framer_resyncs") >= 1
    assert stats.get("packets_received") == 2
    assert stats.get("packets_failed") == 2
    assert stats.get("bytes_received") == 12


async def test_publish_stats_loop(monkeypatch):
    from cync_lan import mqtt_client as m

    m.MQTTClient._instance = None
    c = m.MQTTClient()
    c.publish = AsyncMock(return_value=True)
    stats.inc("packets_failed", 4)
    task = asyncio.create_task(c._publish_stats_loop(interval=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert c.publish.await_count >= 2
    topic, payload = c.publish.await_args.args
    assert topic.endswith("/status/bridge/stats")
    assert json.loads(payload)["packets_failed"] == 4
