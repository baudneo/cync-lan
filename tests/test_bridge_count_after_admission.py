"""The bridge's "Connected TCP devices" count includes the device that connected last.

add_tcp_device() publishes the count when a session is added, but a session only counts as a bridge (_is_bridge:
allowed_to_connect) once can_connect() admits it on its first device packet, and nothing published the count after that.
So each new connection was missing from the count it triggered: with 5 devices connected the sensor read 4.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest_asyncio

from cync_lan import server as server_mod
from cync_lan.devices.session import CyncTCPSession
from cync_lan.structs import GlobalObject

g = GlobalObject()


class FakeReader:
    def feed_eof(self):
        pass


class FakeWriter:
    def __init__(self, ip):
        self.ip = ip

    def close(self):
        pass

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        return (self.ip, 40000) if name == "peername" else None


@pytest_asyncio.fixture
async def srv(monkeypatch):
    async def no_tasks(self):
        return None

    monkeypatch.setattr(CyncTCPSession, "start_tasks", no_tasks)
    server_mod.nCyncServer._instance = None
    s = server_mod.nCyncServer({})
    g.ncync_server = s
    g.mqtt_client = SimpleNamespace(publish=AsyncMock())
    yield s
    g.mqtt_client = None


def last_published_count():
    counts = [c.args[1].decode() for c in g.mqtt_client.publish.await_args_list
              if c.args[0].endswith("/status/bridge/tcp_devices/connected")]
    return counts[-1] if counts else None


async def test_count_includes_each_newly_admitted_device(srv):
    for n, ip in enumerate(("10.0.0.1", "10.0.0.2", "10.0.0.3"), start=1):
        await srv._register_new_connection(FakeReader(), FakeWriter(ip))   # the server's own accept path
        sess = srv.tcp_connections[ip]
        assert await sess.can_connect() is True                            # first device packet admits it
        assert last_published_count() == str(n)


async def test_count_unchanged_when_a_connection_is_rejected(srv, monkeypatch):
    await srv._register_new_connection(FakeReader(), FakeWriter("10.0.0.1"))
    assert await srv.tcp_connections["10.0.0.1"].can_connect() is True
    assert last_published_count() == "1"
    monkeypatch.setattr(srv, "shutting_down", True)
    await srv._register_new_connection(FakeReader(), FakeWriter("10.0.0.2"))
    rejected = srv.tcp_connections["10.0.0.2"]
    monkeypatch.setattr(rejected, "blackhole", AsyncMock())
    assert await rejected.can_connect() is False
    assert last_published_count() == "1"
