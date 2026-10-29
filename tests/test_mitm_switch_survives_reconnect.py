"""A device's "MITM Mode" switch must survive its reconnects.

Seen after devices reconnected: only one of four connected devices still had its switch.
 * same IP (turning MITM off forces a disconnect): the server reuses the session object - close() deleted the switch, and
   the reused session kept mitm_button_added=True, so its next 0x73 never added it again.
 * new IP: the new session added the switch, then the stale old session closed and deleted it for the same node.
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
    def __init__(self, ip="10.0.0.9"):
        self.ip = ip
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        return (self.ip, 40000) if name == "peername" else None


@pytest_asyncio.fixture
async def srv():
    server_mod.nCyncServer._instance = None
    s = server_mod.nCyncServer({})
    g.ncync_server = s
    g.mqtt_client = SimpleNamespace(remove_mitm_button=AsyncMock(), add_mitm_button=AsyncMock(), publish=AsyncMock())
    yield s
    g.mqtt_client = None


def node(nid=1):
    return SimpleNamespace(id=nid, name=f"n{nid}", lp=f"n{nid}:", tcp_session=None)


async def test_closing_a_superseded_session_keeps_the_switch(srv):
    n = node()
    old = CyncTCPSession(FakeReader(), FakeWriter("10.0.0.1"), "10.0.0.1")
    old.node = n
    new = CyncTCPSession(FakeReader(), FakeWriter("10.0.0.2"), "10.0.0.2")
    new.node = n
    n.tcp_session = new                     # the node now lives on the new session
    await old.close()
    g.mqtt_client.remove_mitm_button.assert_not_called()


async def test_closing_the_current_session_removes_the_switch(srv):
    n = node()
    sess = CyncTCPSession(FakeReader(), FakeWriter(), "10.0.0.9")
    sess.node = n
    n.tcp_session = sess
    await sess.close()
    g.mqtt_client.remove_mitm_button.assert_awaited_once()


async def test_reused_session_rearms_its_switch(srv):
    sess = CyncTCPSession(FakeReader(), FakeWriter(), "10.0.0.9")
    sess.mitm_button_added = True
    await sess.existing_init()
    assert sess.mitm_button_added is False   # the first 0x73 on the new socket adds it again


async def test_replacing_a_session_from_the_same_ip_keeps_the_switch(srv, monkeypatch):
    async def no_tasks(self):
        return None

    monkeypatch.setattr(CyncTCPSession, "start_tasks", no_tasks)
    n = node()
    existing = CyncTCPSession(FakeReader(), FakeWriter(), "10.0.0.9")
    existing.node = n
    n.tcp_session = existing
    existing.mitm_button_added = True
    srv.tcp_connections["10.0.0.9"] = existing
    await srv._register_new_connection(FakeReader(), FakeWriter("10.0.0.9"))
    g.mqtt_client.remove_mitm_button.assert_not_called()
    assert srv.tcp_connections["10.0.0.9"] is existing and existing.mitm_button_added is False
