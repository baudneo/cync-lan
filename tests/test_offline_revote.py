"""Stale vote (baudneo/cync-lan#39): a fixture on a wall switch is cut, some of its bulbs being TCP bridges.

The mesh flags the silent bulbs stale ~26 s after power loss, and the watcher reaps their dead bridge sessions
22.5-27.5 s after their last packet. Two things kept bulbs "on" in HA:
 * the vote only ran when a stale report arrived, so if the dead bridges were reaped *afterwards* it was never
   re-checked against the smaller pool;
 * it needed *every* bridge to report the bulb stale, but each bridge only reports some bulbs. On 2026-10-23 a run
   with 8 live bridges got 8/8 votes for two bulbs and 7/8 for the other two, which stayed "on" indefinitely.
Now: a strict majority of distinct live bridges decides, and it is re-checked whenever a session closes.
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
        self.allowed_to_connect = True
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


def ips(*nums):
    return {f"10.0.0.{n}" for n in nums}


def stale():
    return SimpleNamespace(recently_seen=0, name="bulb", sub_id=0)


def test_quorum_is_a_strict_majority_and_a_lone_bridge_decides():
    assert [CyncDevice.stale_quorum(n) for n in (0, 1, 2, 3, 4, 8, 9)] == [1, 1, 2, 2, 3, 5, 5]


async def test_seven_of_eight_bridges_is_enough(env):
    srv, devices, _ = env
    srv.tcp_connections = {f"10.0.0.{i}": FakeSession(f"10.0.0.{i}") for i in range(1, 9)}
    devices[1].stale_voters = ips(1, 2, 3, 4, 5, 6, 7)  # bridge 8 never mentioned the bulb
    devices[2].stale_voters = ips(1, 2, 3, 4)  # 4 < 5: not yet
    await srv.revote_offline()
    assert [d.online for d in devices.values()] == [False, True, True]


async def test_repeat_reports_from_one_bridge_count_once(env):
    srv, devices, _ = env
    srv.tcp_connections = {f"10.0.0.{i}": FakeSession(f"10.0.0.{i}") for i in range(1, 9)}
    dev = devices[1]
    for _ in range(10):
        await dev.handle_entity_update(stale(), from_pkt="0x83", bridge_ip="10.0.0.1")
    assert dev.online and dev.stale_voters == ips(1)
    for n in (2, 3, 4, 5):
        await dev.handle_entity_update(stale(), from_pkt="0x83", bridge_ip=f"10.0.0.{n}")
    assert not dev.online  # 5 distinct bridges of 8


async def test_votes_from_disconnected_bridges_dont_count(env):
    srv, devices, _ = env
    srv.tcp_connections = {f"10.0.0.{i}": FakeSession(f"10.0.0.{i}") for i in range(1, 9)}
    devices[1].stale_voters = ips(1, 2, 3, 9, 10, 11)  # 9-11 are gone
    await srv.revote_offline()
    assert devices[1].online


async def test_reaping_dead_bridges_after_stale_reports_marks_bulbs_offline(env):
    srv, devices, published = env
    # 9 bridges, 3 of them dead but not yet reaped (quorum 5); the 4 live ones that reported are not enough
    for d in devices.values():
        d.stale_voters = ips(1, 2, 3, 4)
    await srv.revote_offline()
    assert all(d.online for d in devices.values())

    # the watcher reaps the dead sessions: pool 9 -> 6 (quorum 4), and the same 4 votes now pass
    for ip in ("10.0.0.7", "10.0.0.8", "10.0.0.9"):
        srv.tcp_connections[ip]._closed = True
    await srv.revote_offline()

    assert not any(d.online for d in devices.values())
    assert stats.get("offline_revotes") == 3


async def test_revote_ignores_devices_with_no_stale_reports(env):
    srv, devices, _ = env
    for ip in list(srv.tcp_connections)[2:]:
        srv.tcp_connections[ip]._closed = True  # pool of 2 (quorum 2)
    devices[1].stale_voters = ips(1, 2)
    devices[2].stale_voters = ips(1)  # short of the quorum
    # devices[3] never reported stale
    await srv.revote_offline()
    assert [d.online for d in devices.values()] == [False, True, True]


async def test_a_valid_report_clears_the_votes(env):
    srv, devices, _ = env
    dev = devices[1]
    dev.stale_voters = ips(1, 2, 3)
    dev.num_late_states = 3
    dev.entities = {}
    # the valid-state path ends in MQTT publishing; only the vote bookkeeping matters here
    async def parse_entity_state(*a, **k):
        return True

    g.mqtt_client.parse_entity_state = parse_entity_state
    g.last_valid_state_ts = 0
    e = SimpleNamespace(recently_seen=1, name="bulb", sub_id=0)
    await dev.handle_entity_update(e, from_pkt="0x83", bridge_ip="10.0.0.1")
    assert dev.stale_voters == set() and dev.num_late_states == 0


async def test_revote_is_idempotent_for_devices_already_offline(env):
    srv, devices, _ = env
    for ip in list(srv.tcp_connections)[1:]:
        srv.tcp_connections[ip]._closed = True  # pool of 1
    devices[1].stale_voters = ips(1)
    devices[1]._online = False
    await srv.revote_offline()
    assert stats.get("offline_revotes") == 0


async def test_closing_a_device_session_triggers_the_revote(env):
    from cync_lan.devices.session import CyncTCPSession

    srv, devices, _ = env
    for d in devices.values():
        d.stale_voters = ips(1, 2, 3, 4)

    async def cancel_all():
        pass

    dead = CyncTCPSession.__new__(CyncTCPSession)
    dead.ip_address = "10.0.0.9"
    dead.is_app = False
    dead.allowed_to_connect = True
    dead.writer = dead.reader = dead.node = None
    dead.capture = None
    dead._closed = dead._closing = False
    dead.tasks = SimpleNamespace(cancel_all=cancel_all)
    dead.is_closed = lambda: dead._closed
    # 6 live bridges + the dead one + 2 more dead-but-unreaped: pool 9, quorum 5, only 4 votes
    srv.tcp_connections = {f"10.0.0.{i}": FakeSession(f"10.0.0.{i}") for i in range(1, 9)}
    srv.tcp_connections["10.0.0.9"] = dead
    await srv.revote_offline()
    assert all(d.online for d in devices.values())

    srv.tcp_connections["10.0.0.7"]._closed = srv.tcp_connections["10.0.0.8"]._closed = True
    await dead.close()  # pool is now 6 (quorum 4)

    assert not any(d.online for d in devices.values())
