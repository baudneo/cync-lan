"""
Multi-home runtime wiring: every lookup that used a bare mesh id now goes through (home_id, dev_id).

Each Cync home is its own BLE mesh and mesh ids restart at 1 in every home, so with two homes "device 5" is two devices.
A bridge (TCP session) relays only its own home's mesh: its home is resolved per session (see registry.HomeResolver and
docs/multi_home.md), and only bridges of a device's home may carry its commands or vote it offline. All data is fake.
"""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from cync_lan import mqtt_client as mqtt_mod
from cync_lan import server as server_mod
from cync_lan.devices import device as device_mod
from cync_lan.devices import proxy as proxy_mod
from cync_lan.devices.device import CyncDevice
from cync_lan.devices.registry import DeviceRegistry
from cync_lan.devices.session import CyncTCPSession
from cync_lan.structs import ControlMessageCallback, GlobalObject

g = GlobalObject()

# nested ids, like a real multi-home account: Cabin has 1-3, House has 1-6, so only 4-6 are unique (to House)
CABIN, HOUSE = 1001, 1002
BRIDGE_TYPE = 137


def make_registry(cabin_bridges=(), house_bridges=(), homes=(CABIN, HOUSE)):
    reg = DeviceRegistry()
    sizes = {CABIN: ("Cabin", 3, cabin_bridges), HOUSE: ("House", 6, house_bridges)}
    for home in homes:
        name, n, bridges = sizes[home]
        reg.add_home(home, name, bridges)
        for i in range(1, n + 1):
            reg.add(CyncDevice(i, dev_type=BRIDGE_TYPE if i == 1 else 53, name=f"{name} {i}", home_id=home,
                               home_name=name, entities={}))
    return reg


class FakeReader:
    def feed_eof(self):
        pass


class FakeWriter:
    def __init__(self, ip="10.0.0.9"):
        self.ip = ip

    def write(self, data):
        pass

    async def drain(self):
        pass

    def is_closing(self):
        return False

    def close(self):
        pass

    async def wait_closed(self):
        pass

    def get_extra_info(self, name):
        return (self.ip, 40000) if name == "peername" else None


@pytest_asyncio.fixture
async def env():
    """A real server holding a two-home registry, with fake MQTT."""
    server_mod.nCyncServer._instance = None
    reg = make_registry()
    srv = server_mod.nCyncServer(reg)
    g.ncync_server = srv
    g.tasks = []
    g.mqtt_client = SimpleNamespace(
        pub_online=AsyncMock(return_value=True), parse_entity_state=AsyncMock(return_value=True),
        add_mitm_button=AsyncMock(), remove_mitm_button=AsyncMock(), publish=AsyncMock(),
        get_startup_topic_state=AsyncMock(return_value=None), topic="cync_lan",
    )
    yield srv, reg
    for t in g.tasks:
        t.cancel()
    g.mqtt_client = None


def session(srv, ip, registry=None, allowed=True):
    s = CyncTCPSession(FakeReader(), FakeWriter(ip), ip, registry=registry or srv.node_devices)
    s.allowed_to_connect = allowed
    s.write = AsyncMock(return_value=True)
    s.queue_id = b"\x00\x00\x00\x07"
    srv.tcp_connections[ip] = s
    return s


def mesh_page(dev_ids, total=None, bridge_type=BRIDGE_TYPE, state=1, bri=50):
    """inner_struct of a 0x73 f9 52 mesh-info page: header to byte 13, then 24-byte records from byte 14."""
    header = bytearray(14)
    header[8] = len(dev_ids)
    header[12] = total if total is not None else len(dev_ids)
    body = bytearray()
    for n, dev_id in enumerate(dev_ids):
        rec = bytearray(24)
        rec[0] = dev_id
        rec[2] = bridge_type if n == 0 else 0
        rec[8], rec[12], rec[16] = state, bri, 254
        body += rec
    return bytes(header + body)


def hello_23(queue_id: int) -> bytes:
    return bytes([0x23, 0, 0, 0, 0x1A, 0x03]) + queue_id.to_bytes(4, "big") + bytes(20)


@pytest.fixture
def updates(monkeypatch):
    """Record every CyncDevice.handle_entity_update as (device key, entity state)."""
    seen = []

    async def record(self, e_state, from_pkt=None, bridge_ip=None):
        seen.append((self.key, e_state))
        return True

    monkeypatch.setattr(CyncDevice, "handle_entity_update", record)
    return seen


# ---- config
async def test_pool_is_per_home_and_unresolved_bridges_are_in_none(env):
    srv, _ = env
    cabin = session(srv, "10.0.0.1")
    house = session(srv, "10.0.0.2")
    unknown = session(srv, "10.0.0.3")
    await cabin._home_resolved(cabin.home.pin(CABIN, "unique_id", "test"))
    await house._home_resolved(house.home.pin(HOUSE, "unique_id", "test"))
    assert srv.get_dev_tcp_pool_sync(CABIN) == [cabin]
    assert await srv.get_dev_tcp_pool(HOUSE) == [house]
    # without a home: every admitted bridge (connection limit, counters), including the unresolved one
    assert srv.get_dev_tcp_pool_sync() == [cabin, house, unknown]


async def test_plain_dict_node_map_is_wrapped_in_a_registry():
    server_mod.nCyncServer._instance = None
    dev = CyncDevice(5, home_id=HOUSE, home_name="House")
    srv = server_mod.nCyncServer({5: dev})
    assert isinstance(srv.node_devices, DeviceRegistry)
    assert srv.node_devices.get_device(HOUSE, 5) is dev


# ---- stale vote / quorum per home
async def test_stale_quorum_counts_only_the_devices_home(env):
    srv, reg = env
    house_bridges = [session(srv, f"10.0.1.{i}") for i in range(1, 3)]
    for s in house_bridges:
        s.home.pin(HOUSE, "unique_id", "test")
    cabin_bridges = [session(srv, f"10.0.2.{i}") for i in range(1, 6)]
    for s in cabin_bridges:
        s.home.pin(CABIN, "unique_id", "test")
    dev = reg.get_device(HOUSE, 2)
    dev._online = True
    # both House bridges report it stale: a majority of House's pool of 2. The 5 Cabin bridges cannot see House's mesh,
    # so they must not count as seats (with a global pool of 7 the quorum would be 4 and it would stay "on")
    for s in house_bridges:
        await dev.handle_entity_update(SimpleNamespace(recently_seen=0, name="x", sub_id=0), bridge_ip=s.ip_address)
    assert dev.online is False


async def test_revote_uses_each_devices_home_pool(env):
    srv, reg = env
    house = session(srv, "10.0.1.1")
    house.home.pin(HOUSE, "unique_id", "test")
    for i in range(1, 4):
        session(srv, f"10.0.2.{i}").home.pin(CABIN, "unique_id", "test")
    house_dev, cabin_dev = reg.get_device(HOUSE, 3), reg.get_device(CABIN, 3)
    for d in (house_dev, cabin_dev):
        d._online = True
        d.stale_voters = {"10.0.1.1"}
    assert await srv.revote_offline() == 1
    # the lone House bridge decides for House; its vote is no vote in Cabin (not a Cabin bridge)
    assert house_dev.online is False and cabin_dev.online is True


# ---- commands
def cmd_bridge(name, home):
    return SimpleNamespace(
        name=name, ready_to_control=True, mitm_mode=False, queue_id=b"\x00\x00\x00\x01", ip_address=name,
        node=SimpleNamespace(id=1), messages=SimpleNamespace(control={}), write=AsyncMock(), home_id=home,
        get_ctrl_msg_id_bytes=lambda: [0x05],
    )


async def test_send_command_asks_only_for_the_devices_home_pool(monkeypatch):
    house = [cmd_bridge(f"h{i}", HOUSE) for i in range(3)]
    get_pool = AsyncMock(return_value=house)
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=get_pool))
    dev = CyncDevice(2, home_id=HOUSE, home_name="House", name="lamp")
    cb = ControlMessageCallback(msg_id=0, message=None, sent_at=0.0, callback=None)
    await dev.send_command(0xD0, 0x0D, 0, bytes([0x11, 0x02, 0x01, 0, 0]), cb, "t:")
    get_pool.assert_awaited_once_with(HOUSE)
    assert sum(b.write.await_count for b in house) == min(device_mod.CYNC_CMD_BROADCASTS, len(house))
    # target_id is still the per-home mesh id
    sent = next(b for b in house if b.write.await_count).write.await_args.args[0]
    assert 2 in sent


async def test_send_command_without_a_bridge_in_the_home_warns_and_drops(monkeypatch, caplog):
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[])))
    dev = CyncDevice(2, home_id=CABIN, home_name="Cabin", name="lamp")
    cb = ControlMessageCallback(msg_id=0, message=None, sent_at=0.0, callback=None)
    with caplog.at_level(logging.WARNING):
        await dev.send_command(0xD0, 0x0D, 0, bytes([0x11, 0x02, 0x01, 0, 0]), cb, "t:")
    assert "no TCP bridge connected for Cync home 'Cabin'" in caplog.text


async def test_unresolved_bridge_never_gets_a_command(env):
    srv, reg = env
    unknown = session(srv, "10.0.0.3")
    assert not unknown.home.resolved
    for home in (CABIN, HOUSE):
        assert unknown not in await srv.get_dev_tcp_pool(home)


# ---- session home
async def test_single_home_resolves_at_creation_and_survives_reconnect(env):
    srv, _ = env
    reg = make_registry(homes=(HOUSE,))
    s = session(srv, "10.0.0.7", registry=reg)
    assert s.home_id == HOUSE and s.home.method == "single_home"
    await s.existing_init()
    assert s.home_id == HOUSE and s.home.method == "single_home"


async def test_bridges_override_survives_reconnect_but_learned_homes_are_reset(env):
    srv, _ = env
    reg = make_registry(cabin_bridges=["10.0.0.8"])
    manual = session(srv, "10.0.0.8", registry=reg)
    assert manual.home_id == CABIN and manual.home.method == "bridges"
    learned = session(srv, "10.0.0.9", registry=reg)
    learned.home.pin(HOUSE, "queue_id", "test")  # what a matched 0x23 queue id does
    assert learned.home_id == HOUSE
    await manual.existing_init()
    await learned.existing_init()
    assert manual.home_id == CABIN
    assert learned.home_id is None and not learned.home.resolved


async def test_queue_id_matching_a_switch_id_resolves_and_is_logged(env, caplog):
    srv, reg = env
    reg.get_device(HOUSE, 2).switch_id = 300000222
    s = session(srv, "10.0.0.4")
    s.mitm_mode = True  # skip the ack / 0xA3 writes (and their sleeps)
    with caplog.at_level(logging.INFO):
        await s._dispatch_device_request(0x23, hello_23(300000222), None, b"", b"", 0, "t:")
    s.tasks.dev_conn_watcher.cancel()
    assert s.home_id == HOUSE and s.home.method == "queue_id"
    assert f"0x23 queue id 0x{300000222:08x} (300000222)" in caplog.text
    assert "equals the switch_id of device 'House 2' (2) in home 'House'" in caplog.text


async def test_unmatched_queue_id_is_logged_and_resolves_nothing(env, caplog):
    srv, _ = env
    s = session(srv, "10.0.0.4")
    s.mitm_mode = True
    with caplog.at_level(logging.INFO):
        await s._dispatch_device_request(0x23, hello_23(0x01020304), None, b"", b"", 0, "t:")
    s.tasks.dev_conn_watcher.cancel()
    assert not s.home.resolved
    assert "0x23 queue id 0x01020304 (16909060) matches no device switch_id" in caplog.text
    # an unplaced bridge gets one WARNING at the hello naming the homes and the fix
    [msg] = [r.getMessage() for r in caplog.records if "Could not work out which Cync home" in r.getMessage()]
    assert "'Cabin' (1001)" in msg and "'House' (1002)" in msg and "10.0.0.4" in msg and "bridges:" in msg


# ---- 0x73 mesh info
async def test_mesh_info_from_an_unplaced_bridge_is_ignored(env, updates):
    """No guessing from ids: ids 1-6 exist in both homes or only in House, and none of it places the bridge."""
    srv, _ = env
    s = session(srv, "10.0.0.5")
    await s._process_73_mesh_info(mesh_page([1, 2, 3], total=6), b"", "t:")
    await s._process_73_mesh_info(mesh_page([5, 6]), b"", "t:")  # ids only House has: still not evidence
    assert updates == [] and s.node is None and not s.home.resolved
    assert s not in await srv.get_dev_tcp_pool(HOUSE)


async def test_same_mesh_id_in_two_homes_reaches_two_devices(env, updates):
    srv, reg = env
    cabin = session(srv, "10.0.0.1")
    house = session(srv, "10.0.0.2")
    cabin.home.pin(CABIN, "bridges", "test")
    house.home.pin(HOUSE, "bridges", "test")
    await cabin._process_73_mesh_info(mesh_page([2]), b"", "t:")
    await house._process_73_mesh_info(mesh_page([2]), b"", "t:")
    assert [k for k, _ in updates] == [(CABIN, 2), (HOUSE, 2)]
    assert cabin.node is reg.get_device(CABIN, 2) and house.node is reg.get_device(HOUSE, 2)


# ---- 0x83 status
def status_83(dev_id):
    data = bytearray(26)
    data[0] = 0x7E
    data[14] = dev_id
    data[19:26] = bytes([1, 1, 40, 254, 0, 0, 0])
    return bytes(data)


async def test_83_status_of_an_unplaced_bridge_is_dropped(env, updates):
    """A status can carry group/room ids or devices added after the export: without a home it is only dropped."""
    srv, _ = env
    s = session(srv, "10.0.0.5")
    for i in (1, 2, 3, 4, 5, 6):  # all of House, some only House has
        await s._parse_83_device_state(status_83(i), 0, 0, "t:")
    assert updates == [] and not s.home.resolved


# ---- MQTT
@pytest_asyncio.fixture
async def mqtt_client():
    mqtt_mod.MQTTClient._instance = None
    reg = make_registry()
    mqtt_mod.g.ncync_server = SimpleNamespace(node_devices=reg, get_dev_tcp_pool=AsyncMock(return_value=[]))
    mqtt_mod.g.env = SimpleNamespace(app_mitm_logging=False)
    c = mqtt_mod.MQTTClient()
    return c, reg


async def test_command_topic_routes_by_home_and_device(mqtt_client):
    c, reg = mqtt_client
    node, sub = c._parse_device_target(f"{CABIN}-2", "t:")
    assert node is reg.get_device(CABIN, 2) and sub is None
    node, sub = c._parse_device_target(f"{HOUSE}-2-3", "t:")
    assert node is reg.get_device(HOUSE, 2) and sub == 3
    assert c._parse_device_target(f"{CABIN}-5", "t:") == (None, None)  # 5 is House-only
    assert c._parse_device_target("x-2", "t:") == (None, None)


async def test_pub_online_uses_the_given_devices_home(mqtt_client):
    c, reg = mqtt_client
    c._connected = True
    c.client = SimpleNamespace(publish=AsyncMock())
    await c.pub_online(reg.get_device(HOUSE, 2), True)
    c.client.publish.assert_awaited_once_with(f"{c.topic}/availability/{HOUSE}-2", b"online", qos=0)


async def test_mitm_switch_only_hits_the_session_of_that_exact_device(mqtt_client):
    c, reg = mqtt_client
    cabin_sess = SimpleNamespace(node=reg.get_device(CABIN, 1), ip_address="10.0.0.1", start_mitm=AsyncMock())
    house_sess = SimpleNamespace(node=reg.get_device(HOUSE, 1), ip_address="10.0.0.2", start_mitm=AsyncMock())
    mqtt_mod.g.ncync_server.get_dev_tcp_pool = AsyncMock(return_value=[cabin_sess, house_sess])
    c.publish = AsyncMock(return_value=True)
    await c._handle_mitm_extra(reg.get_device(HOUSE, 1), f"{HOUSE}-1", b"ON")
    await asyncio.sleep(0)
    house_sess.start_mitm.assert_called_once()
    cabin_sess.start_mitm.assert_not_called()


# ---- MITM log file name
def test_mitm_log_file_name_includes_the_home(monkeypatch, tmp_path):
    monkeypatch.setattr(proxy_mod, "CYNC_MITM_LOG_DIR", str(tmp_path))
    s = CyncTCPSession(FakeReader(), FakeWriter("10.0.0.5"), "10.0.0.5", registry=make_registry())
    s.node = CyncDevice(2, home_id=HOUSE, name="lamp")
    s.name = "lamp"
    s._setup_mitm_logger()
    try:
        assert any(p.name.startswith(f"mitm_dev_{HOUSE}-2-") for p in tmp_path.iterdir())
    finally:
        for h in list(s.mitm_logger.handlers):
            h.close()
            s.mitm_logger.removeHandler(h)
