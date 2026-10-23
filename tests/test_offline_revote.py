"""Stale-vote race (baudneo/cync-lan#39): a fixture whose bulbs are TCP bridges is cut at the wall.

The mesh flags the silent bulbs stale ~26 s after power loss, and the watcher reaps their dead bridge sessions
22.5-27.5 s after their last packet. If the stale reports arrive first, the pool is still full, the vote
(`num_late_states >= len(pool)`) fails, and nothing re-runs it once the pool shrinks.
"""

from types import SimpleNamespace

import pytest_asyncio

from cync_lan import server as server_mod
from cync_lan.devices.device import CyncDevice
from cync_lan.stats import stats
from cync_lan.structs import GlobalObject

g = GlobalObject()


class FakeSession:
    def __init__(self, ip):
        self.ip_address = ip
        self.is_app = False
        self._closed = False

    def is_closed(self):
        return self._closed


@pytest_asyncio.fixture
async def env():
    published = []

    async def pub_online(dev_id, value):
        published.append((dev_id, value))

    server_mod.nCyncServer._instance = None
    g.mqtt_client = SimpleNamespace(pub_online=pub_online, publish=None)
    g.tasks = []
    stats.reset()
    devices = {i: CyncDevice(i) for i in (1, 2, 3)}
    for d in devices.values():
        d._online = True
    srv = server_mod.nCyncServer(devices)
    srv.tcp_connections = {f"10.0.0.{i}": FakeSession(f"10.0.0.{i}") for i in range(1, 10)}
    g.ncync_server = srv
    return srv, devices, published


async def test_reaping_dead_bridges_after_stale_reports_marks_bulbs_offline(env):
    srv, devices, published = env
    # the 6 live bridges each reported the bulb stale; 3 dead bridges are still in the pool (6 < 9)
    for d in devices.values():
        d.num_late_states = 6
    await srv.revote_offline()
    assert all(d.online for d in devices.values())

    # the watcher reaps the 3 dead sessions: pool 9 -> 6, the vote now passes
    for ip in ("10.0.0.7", "10.0.0.8", "10.0.0.9"):
        srv.tcp_connections[ip]._closed = True
    await srv.revote_offline()

    assert not any(d.online for d in devices.values())
    assert stats.get("offline_revotes") == 3


async def test_revote_ignores_devices_with_no_stale_reports(env):
    srv, devices, _ = env
    for ip in list(srv.tcp_connections)[2:]:
        srv.tcp_connections[ip]._closed = True  # pool of 2
    devices[1].num_late_states = 2  # votes in
    devices[2].num_late_states = 1  # short of the pool
    devices[3].num_late_states = 0  # healthy, never reported stale
    await srv.revote_offline()
    assert [d.online for d in devices.values()] == [False, True, True]


async def test_revote_is_idempotent_for_devices_already_offline(env):
    srv, devices, _ = env
    for ip in list(srv.tcp_connections)[1:]:
        srv.tcp_connections[ip]._closed = True  # pool of 1
    devices[1].num_late_states = 1
    devices[1]._online = False
    await srv.revote_offline()
    assert stats.get("offline_revotes") == 0


async def test_closing_a_device_session_triggers_the_revote(env):
    from cync_lan.devices.session import CyncTCPSession

    srv, devices, _ = env
    for d in devices.values():
        d.num_late_states = 6

    async def cancel_all():
        pass

    dead = CyncTCPSession.__new__(CyncTCPSession)
    dead.ip_address = "10.0.0.9"
    dead.is_app = False
    dead.writer = dead.reader = dead.node = None
    dead._closed = dead._closing = False
    dead.tasks = SimpleNamespace(cancel_all=cancel_all)
    dead.is_closed = lambda: dead._closed
    srv.tcp_connections = {f"10.0.0.{i}": FakeSession(f"10.0.0.{i}") for i in range(1, 7)}
    srv.tcp_connections["10.0.0.9"] = dead  # pool of 7 > 6 stale votes

    await dead.close()

    assert not any(d.online for d in devices.values())  # pool is 6 once the dead session closes
