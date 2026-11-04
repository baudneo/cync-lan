"""
End-to-end multi-home tests: one cync_mesh.yaml with several Cync homes, driven through the real code paths.

Every Cync home is its own BLE mesh and mesh ids restart at 1 in each home, so with several homes "device 5" names
several devices. Devices are keyed by (home_id, dev_id); each bridge (TCP session) works out which home it relays (see
docs/multi_home.md) and only carries that home's state and commands.

What is real here: the config parser (tests/fixtures/multi_home_mesh.yaml, sanitized, ALL DATA FAKE), the TCP server's
connection registration and admission, the packet framer and handlers parsing crafted packet bytes, the MQTT client's
command parsing, state publishing and Home Assistant discovery. What is fake: the sockets (a writer that records every
byte the server sends), the MQTT broker (records every publish), and the handlers' short protocol sleeps (0.5 s / 1.5 s
after a 0x23 hello).
"""

import asyncio
import copy
import json
import logging
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import yaml

from cync_lan import mqtt_client as mqtt_mod
from cync_lan import server as server_mod
from cync_lan.devices import device as device_mod
from cync_lan.devices import handlers as handlers_mod
from cync_lan.devices.session import CyncTCPSession
from cync_lan.packet import PacketBuilder
from cync_lan.structs import GlobalObject
from cync_lan.utils import build_nodes, parse_config

g = GlobalObject()

FIXTURE = Path(__file__).parent / "fixtures" / "multi_home_mesh.yaml"
CABIN, HOUSE, BARN, EMPTY = 100000001, 100000002, 100000003, 100000004
SIZES = {CABIN: 6, HOUSE: 12, BARN: 20}
NAMES = {CABIN: "Cabin", HOUSE: "House", BARN: "Barn"}
NO_METADATA_TYPE = 112  # model_info does not know it yet: discovery skips it (pre-existing behaviour)
UNMATCHED_QID = 0x0A0B0C0D  # a queue id that is no home id and no switch_id


def raw_cfg() -> dict:
    return yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))


def only_homes(cfg: dict, *names: str) -> dict:
    cfg = copy.deepcopy(cfg)
    cfg["exported_homes"] = {k: v for k, v in cfg["exported_homes"].items() if k in names}
    return cfg


# ---- crafted packets (layouts: docs/protocol.md sections 3-5)
def hello_23(queue_id: int) -> bytes:
    """0x23 auth/hello as captured in docs/packet_structure.md (31 bytes), auth code zeroed, queue id at [6:10]."""
    return bytes([0x23, 0x00, 0x00, 0x00, 0x1A, 0x03]) + queue_id.to_bytes(4, "big") + b"\x00\x10" + bytes(16) + b"\x00\x00\x3c"


def mesh_info_73(queue_id: bytes, records, total=None) -> bytes:
    """
    0x73 mesh-info reply page (inner control bytes F9 52). ``records``: (dev_id, dev_type, power, brightness) tuples;
    the first one is the bridge itself, the only record that carries its device type. inner[8] = records in this
    page, inner[12] = total devices, 24-byte records from inner[14].
    """
    header = bytearray(14)
    header[0] = 0x0B
    header[4:6] = b"\xf9\x52"
    header[8] = len(records)
    header[12] = len(records) if total is None else total
    body = bytearray()
    for n, (dev_id, dev_type, power, bri) in enumerate(records):
        rec = bytearray(24)
        rec[0] = dev_id
        rec[2] = dev_type if n == 0 else 0
        rec[8], rec[12], rec[16] = power, bri, 254
        rec[20:23] = bytes([10, 20, 30])
        body += rec
    inner = bytes(header + body)
    assert 0x7E not in inner  # the handler cuts the inner packet at the first 0x7E
    payload = bytes([0x7E]) + inner + bytes([sum(inner[5:]) % 256, 0x7E])
    return PacketBuilder.build_outer_packet(0x73, queue_id, payload, msg_id=b"\x00\x01\x00")


def status_83(queue_id: bytes, dev_id: int, recently_seen=1, power=1, bri=40) -> bytes:
    """0x83 device state (inner control bytes FA DB, inner[7] == 0x13): dev id at [14], state at [19:26]."""
    pd = bytearray(28)
    pd[0] = 0x7E
    pd[5:7] = b"\xfa\xdb"
    pd[7] = 0x13
    pd[14] = dev_id
    pd[19:26] = bytes([recently_seen, power, bri, 254, 0, 0, 0])
    pd[26] = sum(pd[6:26]) % 256
    pd[27] = 0x7E
    return PacketBuilder.build_outer_packet(0x83, queue_id, bytes(pd), msg_id=b"\x00\x02\x00")


def control_reply_73(queue_id: bytes, ctrl_msg_id: int) -> bytes:
    """A device's success reply to our control packet (F9 D0, inner[7] == 1)."""
    pd = bytes([0x7E, ctrl_msg_id, 0, 0, 0, 0xF9, 0xD0, 0x01, 0x00, 0x7E])
    return PacketBuilder.build_outer_packet(0x73, queue_id, pd, msg_id=b"\x00\x03\x00")


# ---- fakes
class FakeReader:
    def feed_eof(self):
        pass


class RecordingWriter:
    """Stands in for the TLS socket of one bridge: records every packet the server sends to it."""

    def __init__(self, ip: str):
        self.ip = ip
        self.sent = []

    def write(self, data):
        self.sent.append(bytes(data))

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

    def control_packets(self):
        """Control commands only (0x73, inner F8 <op>): not the mesh-info request (F8 52) or mesh ack (F8 AF)."""
        return [p for p in self.sent if p[0] == 0x73 and len(p) > 27 and p[17] == 0xF8 and p[18] not in (0x52, 0xAF)]


class FakeBroker:
    """Stands in for aiomqtt.Client: records every publish."""

    def __init__(self):
        self.published = []

    async def publish(self, topic, payload=None, **kwargs):
        self.published.append((topic, payload))

    def topics(self, prefix=""):
        return [t for t, _ in self.published if t.startswith(prefix)]


class _Topic:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value


class MqttMsg:
    def __init__(self, topic, payload):
        self.topic = _Topic(topic)
        self.payload = payload


class _FastProtocolSleep:
    """The handlers module's asyncio, except that the short protocol waits after a 0x23 hello do not slow the tests
    down. Long sleeps (the 90 s mesh refresh) are real, so that task just waits until it is cancelled."""

    def __getattr__(self, name):
        return getattr(asyncio, name)

    @staticmethod
    async def sleep(delay, result=None):
        await asyncio.sleep(delay if delay > 5 else 0)
        return result


class World:
    def __init__(self, registry, srv, mqtt):
        self.reg, self.srv, self.mqtt = registry, srv, mqtt
        self.broker: FakeBroker = mqtt.client
        self.writers = {}

    async def connect(self, ip: str, queue_id: int) -> CyncTCPSession:
        """A bridge connects (real server registration) and says hello (real 0x23 handling, admission included)."""
        writer = RecordingWriter(ip)
        self.writers[ip] = writer
        await self.srv._register_new_connection(FakeReader(), writer)
        s = self.srv.tcp_connections[ip]
        await s.parse_raw_data(hello_23(queue_id))
        return s

    async def feed(self, s: CyncTCPSession, data: bytes):
        await s.parse_raw_data(data)

    async def command(self, target: str, payload: bytes) -> bool:
        return await self.mqtt.async_parse_mqtt_msg(MqttMsg(f"{self.mqtt.topic}/set/{target}", payload))

    def snapshot(self):
        """Everything a state update could touch, per device key."""
        return {
            k: (d.online, {sid: e.model_dump() for sid, e in d.entities.items()}, set(d.stale_voters))
            for k, d in self.reg.items()
        }

    def status_topics(self):
        return [t for t in self.broker.topics(f"{self.mqtt.topic}/status/") if "/bridge/" not in t]


async def _build_world(monkeypatch, registry) -> World:
    async def no_tasks(self):
        return None

    # receive/callback-cleanup loops need a real socket; packets are fed straight into parse_raw_data instead
    monkeypatch.setattr(CyncTCPSession, "start_tasks", no_tasks)
    monkeypatch.setattr(handlers_mod, "asyncio", _FastProtocolSleep())
    monkeypatch.setattr(g, "uuid", uuid.UUID(int=1))
    monkeypatch.setattr(g, "tasks", [])
    server_mod.nCyncServer._instance = None
    srv = server_mod.nCyncServer(registry, home_grace_secs=0)
    mqtt_mod.MQTTClient._instance = None
    monkeypatch.setattr(g, "ncync_server", srv)
    c = mqtt_mod.MQTTClient()
    c.client = FakeBroker()
    c._connected = True
    c.get_startup_topic_state = AsyncMock(return_value=None)  # would open a second broker connection
    monkeypatch.setattr(g, "mqtt_client", c)
    return World(registry, srv, c)


async def _teardown(w: World):
    for s in list(w.srv.tcp_connections.values()):
        await s.tasks.cancel_all()
    await w.srv._stop_home_grace()
    pending = [t for t in g.tasks if t is not None and not t.done()]
    for t in pending:
        t.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    server_mod.nCyncServer._instance = None
    mqtt_mod.MQTTClient._instance = None


@pytest_asyncio.fixture
async def world(monkeypatch):
    w = await _build_world(monkeypatch, build_nodes(raw_cfg()))
    yield w
    await _teardown(w)


@pytest_asyncio.fixture
async def make_world(monkeypatch):
    """A world built from a modified copy of the fixture config."""
    worlds = []

    async def make(cfg: dict) -> World:
        w = await _build_world(monkeypatch, build_nodes(cfg))
        worlds.append(w)
        return w

    yield make
    for w in worlds:
        await _teardown(w)


def qid(n: int) -> bytes:
    return n.to_bytes(4, "big")


# =====================================================================================================================
# 1. loading
async def test_all_38_devices_load_with_distinct_keys(caplog):
    with caplog.at_level(logging.WARNING):
        reg = await parse_config(FIXTURE)
    assert len(reg) == 38
    expected = {(h, i) for h, n in SIZES.items() for i in range(1, n + 1)}
    assert set(reg) == expected
    # the empty home is not registered (and says so); the other three are, with their names
    assert reg.home_ids() == [CABIN, HOUSE, BARN]
    assert reg.home(EMPTY) is None
    assert "No devices found in config for: Empty (ID: 100000004)" in caplog.text
    assert {h: reg.home_name(h) for h in reg.home_ids()} == NAMES
    for h, n in SIZES.items():
        devs = reg.in_home(h)
        assert [d.id for d in devs] == list(range(1, n + 1))
        assert all(d.home_id == h and d.home_name == NAMES[h] and d.key == (h, d.id) for d in devs)
    # one CyncDevice object per key, and the HA id strings never collide
    assert len({id(d) for d in reg.values()}) == 38
    assert len({d.hass_id for d in reg.values()}) == 38
    # the nesting the resolver has to cope with: 1-6 everywhere, 7-12 in House and Barn, 13-20 only in Barn
    assert reg.homes_with(3) == {CABIN, HOUSE, BARN}
    assert reg.homes_with(9) == {HOUSE, BARN}
    plug = reg.get_device(HOUSE, 7)
    assert plug.type == 67 and sorted(plug.entities) == [1, 2] and plug.has_multi_entities


def test_disabled_devices_and_fully_disabled_homes_are_left_out():
    cfg = raw_cfg()
    cfg["exported_homes"]["House"]["devices"][5]["enabled"] = False
    for dev in cfg["exported_homes"]["Cabin"]["devices"].values():
        dev["enabled"] = "no"
    reg = build_nodes(cfg)
    assert reg.home_ids() == [HOUSE, BARN]  # Cabin has no enabled device: not a home the bridges can resolve to
    assert reg.get_device(HOUSE, 5) is None and len(reg.in_home(HOUSE)) == 11
    assert reg.get_device(BARN, 5) is not None  # the same mesh id in another home is a different device
    assert len(reg) == 31
    # with Cabin gone, 1-6 still exist twice: nothing about House/Barn is unique by id alone
    assert reg.homes_with(1) == {HOUSE, BARN}


# =====================================================================================================================
# 2. Home Assistant discovery
def _discovery_configs(w: World) -> dict:
    """unique_id -> discovery payload for every non-empty config published under the HA topic."""
    out = {}
    for topic, payload in w.broker.published:
        if topic.startswith(f"{w.mqtt.ha_topic}/") and topic.endswith("/config") and payload:
            conf = json.loads(payload)
            assert conf["unique_id"] not in out, f"duplicate unique_id {conf['unique_id']}"
            out[conf["unique_id"]] = conf
    return out


async def _run_discovery(w: World):
    w.mqtt.create_bridge_device = AsyncMock(return_value=True)  # the bridge's own entities, not under test
    assert await w.mqtt.homeassistant_discovery() is True
    return _discovery_configs(w)


def _expected_entities(reg, home_id):
    """unique_id -> (object_id, command topic tail) in the pre-multi-home format."""
    out = {}
    for d in reg.in_home(home_id):
        if d.type == NO_METADATA_TYPE:
            continue
        if d.has_multi_entities:
            for ep in d.entities:
                out[f"{home_id}_{d.id}_{ep}"] = (f"cync_lan_{home_id}_{d.id}_{ep}", f"{home_id}-{d.id}-{ep}")
        else:
            out[f"{home_id}_{d.id}"] = (f"cync_lan_{home_id}_{d.id}", f"{home_id}-{d.id}")
    return out


async def test_discovery_publishes_every_device_of_every_home_with_distinct_unique_ids(world, caplog):
    with caplog.at_level(logging.WARNING):
        confs = await _run_discovery(world)
    expected = {}
    for h in SIZES:
        expected.update(_expected_entities(world.reg, h))
    # 6 Cabin + 11 House + 2 House plug outlets + 18 Barn (the two type-112 devices have no model metadata yet)
    assert len(expected) == 37
    assert set(confs) == set(expected)
    assert caplog.text.count("has no metadata") == 2
    # the same mesh id in three homes: three HA devices, three topics
    for h in (CABIN, HOUSE, BARN):
        assert confs[f"{h}_3"]["command_topic"] == f"{world.mqtt.topic}/set/{h}-3"
    assert len({c["command_topic"] for c in confs.values()}) == 37
    assert len({c["object_id"] for c in confs.values()}) == 37


async def test_single_home_discovery_strings_are_exactly_the_pre_change_format(make_world):
    w = await make_world(only_homes(raw_cfg(), "House"))
    confs = await _run_discovery(w)
    t = w.mqtt.topic
    expected = _expected_entities(w.reg, HOUSE)
    assert set(confs) == set(expected)
    for unique_id, (object_id, tail) in expected.items():
        conf = confs[unique_id]
        assert conf["object_id"] == object_id
        assert conf["command_topic"] == f"{t}/set/{tail}"
        assert conf["state_topic"] == f"{t}/status/{tail}"
        assert conf["avty"][0]["t"] == f"{t}/availability/{tail}"
    # spot check against literal strings, so a format change can not hide behind the helper above
    assert confs["100000002_5"]["object_id"] == "cync_lan_100000002_5"
    assert confs["100000002_5"]["command_topic"] == f"{t}/set/100000002-5"
    assert confs["100000002_7_2"]["command_topic"] == f"{t}/set/100000002-7-2"
    assert confs["100000002_5"]["device"]["identifiers"] == ["100000002_5"]


async def test_a_homes_discovery_payloads_do_not_change_when_other_homes_are_added(world, make_world):
    multi = await _run_discovery(world)
    single_world = await make_world(only_homes(raw_cfg(), "House"))
    single = await _run_discovery(single_world)
    for unique_id, conf in single.items():
        assert multi[unique_id] == conf


# =====================================================================================================================
# 3. MQTT commands go to the device's own home only
async def test_mqtt_command_is_written_only_to_the_bridge_of_that_home(world):
    cabin = await world.connect("10.0.1.1", CABIN)
    house = await world.connect("10.0.2.1", HOUSE)
    barn = await world.connect("10.0.3.1", BARN)
    assert (cabin.home_id, house.home_id, barn.home_id) == (CABIN, HOUSE, BARN)
    assert {s.home.method for s in (cabin, house, barn)} == {"queue_id"}
    for s in (cabin, house, barn):
        # the hello was answered and the bridge asked for its mesh: a normal connection
        assert s.ready_to_control
        assert PacketBuilder.build_mesh_info_request(s.queue_id) in world.writers[s.ip_address].sent
    for wr in world.writers.values():
        wr.sent.clear()

    assert await world.command("100000002-5", b'{"state": "ON"}') is True

    assert world.writers["10.0.1.1"].sent == [] and world.writers["10.0.3.1"].sent == []
    [pkt] = world.writers["10.0.2.1"].control_packets()
    assert pkt[5:9] == qid(HOUSE)  # addressed with the House bridge's queue id
    assert pkt[18] == 0xD0  # power op
    assert pkt[26] == 5 and pkt[27] == 0  # target = the per-home mesh id, whole device
    assert pkt[29:34] == bytes([0x11, 0x02, 0x01, 0x00, 0x00])  # power ON

    # the device ACKs; the callback publishes the new state for the House device only
    await world.feed(house, control_reply_73(house.queue_id, pkt[13]))
    assert world.status_topics() == [f"{world.mqtt.topic}/status/100000002-5"]
    assert world.reg.get_device(HOUSE, 5).entities[0].power == 1
    assert world.reg.get_device(CABIN, 5).entities[0].power == 0
    assert world.reg.get_device(BARN, 5).entities[0].power == 0


async def test_multi_outlet_and_other_home_commands_route_by_home(world):
    await world.connect("10.0.1.1", CABIN)
    await world.connect("10.0.2.1", HOUSE)
    await world.connect("10.0.3.1", BARN)
    for wr in world.writers.values():
        wr.sent.clear()
    await world.command("100000002-7-2", b"ON")  # House plug, right outlet
    [pkt] = world.writers["10.0.2.1"].control_packets()
    assert (pkt[26], pkt[27]) == (7, 2)
    await world.command("100000003-7", b"OFF")  # Barn device 7: same mesh id, other home
    [pkt] = world.writers["10.0.3.1"].control_packets()
    assert (pkt[26], pkt[27]) == (7, 0) and pkt[5:9] == qid(BARN)
    assert world.writers["10.0.1.1"].control_packets() == []
    assert len(world.writers["10.0.2.1"].control_packets()) == 1
    # Cabin has no device 7: unknown target, nothing is sent anywhere
    assert await world.command("100000001-7", b"ON") is False
    assert sum(len(wr.control_packets()) for wr in world.writers.values()) == 2


# =====================================================================================================================
# 4. device state from a bridge lands in that bridge's home only
async def test_mesh_info_from_a_cabin_bridge_updates_only_cabin_devices(world):
    cabin = await world.connect("10.0.1.1", CABIN)
    before = world.snapshot()
    records = [(i, 137, 1, 10 * i) for i in range(1, 7)]
    await world.feed(cabin, mesh_info_73(cabin.queue_id, records))

    after = world.snapshot()
    for key in world.reg:
        if key[0] != CABIN:
            assert after[key] == before[key], f"{key} was touched by a Cabin bridge"
    for i in range(1, 7):
        dev = world.reg.get_device(CABIN, i)
        assert dev.online and dev.entities[0].power == 1 and dev.entities[0].brightness == 10 * i
    # the bridge's own node is the Cabin device 1, not House or Barn device 1
    assert cabin.node is world.reg.get_device(CABIN, 1) and cabin.node.tcp_session is cabin
    assert sorted(set(world.status_topics())) == [f"{world.mqtt.topic}/status/{CABIN}-{i}" for i in range(1, 7)]
    # and the page was acked: mesh status ack, then the 0x73 ack
    assert world.writers["10.0.1.1"].sent[-2:] == [
        PacketBuilder.build_mesh_status_ack(cabin.queue_id),
        PacketBuilder.build_73_ack(cabin.queue_id, b"\x00\x01\x00"),
    ]


async def test_83_status_from_a_cabin_bridge_updates_only_cabin_device(world):
    cabin = await world.connect("10.0.1.1", CABIN)
    before = world.snapshot()
    await world.feed(cabin, status_83(cabin.queue_id, 4, power=1, bri=77))
    after = world.snapshot()
    assert [k for k in world.reg if after[k] != before[k]] == [(CABIN, 4)]
    assert world.reg.get_device(CABIN, 4).entities[0].brightness == 77
    assert world.status_topics() == [f"{world.mqtt.topic}/status/{CABIN}-4"]
    assert world.writers["10.0.1.1"].sent[-1] == PacketBuilder.build_83_ack(b"\x00\x02\x00")


async def test_type_67_status_bitmask_lands_on_the_house_plug_outlets(world):
    house = await world.connect("10.0.2.1", HOUSE)
    await world.feed(house, status_83(house.queue_id, 7, power=1, bri=0b10))  # right outlet on, left off
    plug = world.reg.get_device(HOUSE, 7)
    assert (plug.entities[1].power, plug.entities[2].power) == (0, 1)
    assert world.reg.get_device(BARN, 7).entities[0].power == 0
    assert sorted(set(world.status_topics())) == [f"{world.mqtt.topic}/status/{HOUSE}-7-1",
                                                  f"{world.mqtt.topic}/status/{HOUSE}-7-2"]


# =====================================================================================================================
# 5. working out a bridge's home
async def test_queue_id_equal_to_a_home_id_resolves_and_is_logged(world, caplog):
    with caplog.at_level(logging.INFO):
        s = await world.connect("10.0.3.1", BARN)
    assert s.home_id == BARN and s.home.method == "queue_id"
    assert f"0x23 queue id 0x{BARN:08x} ({BARN}) equals the id of home 'Barn'" in caplog.text
    assert s in world.srv.get_dev_tcp_pool_sync(BARN)


async def test_queue_id_equal_to_a_devices_switch_id_resolves(make_world, caplog):
    cfg = raw_cfg()
    cfg["exported_homes"]["House"]["devices"][2]["switch_id"] = 300000222
    w = await make_world(cfg)
    with caplog.at_level(logging.INFO):
        s = await w.connect("10.0.2.2", 300000222)
    assert s.home_id == HOUSE and s.home.method == "queue_id"
    assert "switch_id" in s.home.match.detail
    assert f"0x23 queue id 0x{300000222:08x} (300000222)" in caplog.text


async def test_bridges_ip_override_resolves_at_creation(make_world):
    cfg = raw_cfg()
    cfg["exported_homes"]["Cabin"]["bridges"] = ["10.0.9.9"]
    w = await make_world(cfg)
    writer = RecordingWriter("10.0.9.9")
    await w.srv._register_new_connection(FakeReader(), writer)
    s = w.srv.tcp_connections["10.0.9.9"]
    assert s.home_id == CABIN and s.home.method == "bridges"  # before it sent a single packet
    w.writers["10.0.9.9"] = writer
    await s.parse_raw_data(hello_23(UNMATCHED_QID))
    assert s.home_id == CABIN  # a later signal never overrides the first resolution
    before = w.snapshot()
    await w.feed(s, mesh_info_73(s.queue_id, [(1, 137, 1, 50), (2, 137, 1, 60), (3, 137, 0, 0)]))
    changed = sorted(k for k in w.reg if w.snapshot()[k] != before[k])
    assert changed == [(CABIN, 1), (CABIN, 2), (CABIN, 3)]


async def test_fingerprint_resolves_barn_once_its_ids_are_reported_and_applies_held_back_records(world, caplog):
    s = await world.connect("10.0.3.7", UNMATCHED_QID)
    assert not s.home.resolved
    before = world.snapshot()
    # the bridge is device 3 (type 53: House-3 and Barn-3 match, Cabin-3 is a 137), then 9 (House and Barn), then 15
    # (only Barn). One id that only Barn has is not proof (House's config may just be missing a device), so nothing is
    # decided until the rest of Barn reports: then House lacks 13-20 and Barn has nothing unreported.
    await world.feed(s, mesh_info_73(s.queue_id, [(3, 53, 1, 30), (9, 0, 1, 90)], total=20))
    await world.feed(s, mesh_info_73(s.queue_id, [(15, 0, 1, 15)], total=20))
    assert not s.home.resolved and s.home.candidates == frozenset({CABIN, HOUSE, BARN})
    assert world.snapshot() == before
    rest = [i for i in range(1, 21) if i not in (3, 9, 15)]
    with caplog.at_level(logging.INFO):
        await world.feed(s, mesh_info_73(s.queue_id, [(i, 0, 1, 40 + i) for i in rest], total=20))
    assert s.home_id == BARN and s.home.method == "fingerprint"
    [line] = [r for r in caplog.records if "Cync home resolved to 'Barn' (100000003) by fingerprint" in r.getMessage()]
    # inferred from ids only: logged at WARNING, with the deciding evidence and how to pin it
    assert line.levelno == logging.WARNING
    assert "'House' (100000002) lacks reported id(s) 13-20" in line.getMessage()
    assert "bridges:" in line.getMessage() and "10.0.3.7" in line.getMessage()
    after = world.snapshot()
    changed = {k for k in world.reg if after[k] != before[k]}
    assert {(BARN, 3), (BARN, 9), (BARN, 15)} <= changed and all(h == BARN for h, _ in changed)
    assert world.reg.get_device(BARN, 9).entities[0].brightness == 90
    assert s.node is world.reg.get_device(BARN, 3)
    # and now it carries Barn's commands
    world.writers["10.0.3.7"].sent.clear()
    await world.command("100000003-15", b"ON")
    [pkt] = world.writers["10.0.3.7"].control_packets()
    assert pkt[26] == 15
    assert "Could not work out" not in caplog.text


async def test_device_added_after_the_export_does_not_send_a_house_bridge_to_barn(world, caplog):
    """
    A 13th House device was added in the app after the export: the mesh gives it id 13, which the config only has in
    Barn. A House bridge reporting 1-13 must not be taken for a Barn bridge (Barn has 14-20 unreported), so no Barn
    state is overwritten and Barn commands never go into the House mesh.
    """
    s = await world.connect("10.0.2.9", UNMATCHED_QID)
    before = world.snapshot()
    with caplog.at_level(logging.WARNING):
        await world.feed(s, mesh_info_73(s.queue_id, [(2, 53, 1, 20)] + [(i, 0, 1, 20) for i in range(1, 14) if i != 2]))
        await world.feed(s, status_83(s.queue_id, 13, bri=99))
    assert not s.home.resolved and s.home.candidates == frozenset({HOUSE, BARN})
    assert world.snapshot() == before
    assert s not in world.srv.get_dev_tcp_pool_sync(BARN)
    [msg] = [r.getMessage() for r in caplog.records if "Could not work out which Cync home" in r.getMessage()]
    assert "'House' (100000002)" in msg and "'Barn' (100000003)" in msg and "re-export" in msg


async def test_ambiguous_bridge_applies_nothing_warns_once_and_gets_no_commands(world, caplog):
    # a Cabin bridge (device 1, type 137) reporting all of Cabin, 1-6: those ids also exist in House and Barn, and Barn-1
    # is a 137 too, so Cabin and Barn both stay possible (House-1 is a 53: ruled out by the bridge's type)
    s = await world.connect("10.0.1.5", UNMATCHED_QID)
    before = world.snapshot()
    world.broker.published.clear()
    page = mesh_info_73(s.queue_id, [(i, 137, 1, 40) for i in range(1, 7)])
    with caplog.at_level(logging.WARNING):
        await world.feed(s, page)
        await world.feed(s, page)  # the 90 s refresh repeats the sequence
        await world.feed(s, status_83(s.queue_id, 2, bri=99))  # 2 is in every home: dropped, not guessed
    assert not s.home.resolved and s.home.candidates == frozenset({CABIN, BARN})
    assert world.snapshot() == before
    assert world.status_topics() == []
    assert s.node is None
    warnings = [r.getMessage() for r in caplog.records if "Could not work out which Cync home" in r.getMessage()]
    assert len(warnings) == 1
    msg = warnings[0]
    assert "'Cabin' (100000001)" in msg and "'Barn' (100000003)" in msg and "'House'" not in msg
    assert "10.0.1.5" in msg and f"0x{UNMATCHED_QID:08x}" in msg and 'bridges: ["10.0.1.5"]' in msg
    assert "docs/multi_home.md" in msg
    # never used for commands: in no home's pool, and a Cabin command (Cabin has no other bridge) is dropped
    assert all(s not in world.srv.get_dev_tcp_pool_sync(h) for h in SIZES)
    world.writers["10.0.1.5"].sent.clear()
    with caplog.at_level(logging.WARNING):
        await world.command("100000001-2", b"ON")
    assert world.writers["10.0.1.5"].control_packets() == []
    assert "no TCP bridge connected for Cync home 'Cabin' (100000001)" in caplog.text


# =====================================================================================================================
# 6. a home without a bridge
async def test_home_without_a_bridge_warns_and_goes_offline_after_the_grace(world, caplog):
    for d in world.reg.values():
        d._online = True
    world.srv.home_grace_secs = 0.3
    # what server.start() does once it is listening
    tasks = {h: world.srv.start_home_grace(h) for h in world.reg.home_ids()}
    with caplog.at_level(logging.WARNING):
        house = await world.connect("10.0.2.1", HOUSE)  # a House bridge resolves in time
        await asyncio.wait(list(tasks.values()))
    assert house.home_id == HOUSE
    assert tasks[HOUSE].cancelled()
    assert not tasks[CABIN].cancelled() and not tasks[BARN].cancelled()
    grace = [r.getMessage() for r in caplog.records if "No TCP bridge for Cync home" in r.getMessage()]
    assert len(grace) == 2
    assert any("'Cabin' (100000001)" in m and "6 device(s)" in m for m in grace)
    assert any("'Barn' (100000003)" in m and "20 device(s)" in m for m in grace)
    assert all(not d.online for h in (CABIN, BARN) for d in world.reg.in_home(h))
    assert all(d.online for d in world.reg.in_home(HOUSE))
    await asyncio.gather(*g.tasks)  # the availability publishes the online setter queued
    offline = [t for t, p in world.broker.published if p == b"offline"]
    assert f"{world.mqtt.topic}/availability/{CABIN}-1" in offline
    assert not any(f"/availability/{HOUSE}-" in t for t in offline)


# =====================================================================================================================
# 7. stale quorum per home
async def test_stale_quorum_is_counted_among_the_devices_home_bridges_only(world):
    house = [await world.connect(f"10.0.2.{i}", HOUSE) for i in (1, 2)]
    cabin = [await world.connect(f"10.0.1.{i}", CABIN) for i in (1, 2, 3)]
    assert len(world.srv.get_dev_tcp_pool_sync()) == 5  # a global quorum would be 3
    await world.feed(house[0], status_83(house[0].queue_id, 9))  # House-9 seen: online
    dev = world.reg.get_device(HOUSE, 9)
    assert dev.online
    await world.feed(house[0], status_83(house[0].queue_id, 9, recently_seen=0))
    assert dev.online  # 1 of a House quorum of 2
    await world.feed(house[1], status_83(house[1].queue_id, 9, recently_seen=0))
    assert not dev.online  # 2 of 2 House bridges: offline, though only 2 of 5 bridges overall voted
    assert dev.stale_voters == {"10.0.2.1", "10.0.2.2"}

    # Cabin bridges report their own device 3 stale: House-3 and Barn-3 are other devices and get no vote
    for d in (world.reg.get_device(CABIN, 3), world.reg.get_device(HOUSE, 3), world.reg.get_device(BARN, 3)):
        d._online = True
    for s in cabin[:2]:
        await world.feed(s, status_83(s.queue_id, 3, recently_seen=0))
    assert not world.reg.get_device(CABIN, 3).online  # 2 of a Cabin quorum of 2 (pool 3)
    assert world.reg.get_device(HOUSE, 3).online and world.reg.get_device(HOUSE, 3).stale_voters == set()
    assert world.reg.get_device(BARN, 3).online and world.reg.get_device(BARN, 3).stale_voters == set()


# =====================================================================================================================
# 8. single home: behaves as before
async def test_single_home_session_home_is_set_at_creation_and_commands_go_to_any_bridge(make_world, caplog):
    w = await make_world(only_homes(raw_cfg(), "House"))
    assert w.reg.home_ids() == [HOUSE]
    writer = RecordingWriter("10.0.2.1")
    await w.srv._register_new_connection(FakeReader(), writer)
    first = w.srv.tcp_connections["10.0.2.1"]
    assert first.home_id == HOUSE and first.home.method == "single_home"  # before any packet
    w.writers["10.0.2.1"] = writer
    await first.parse_raw_data(hello_23(0x01020304))  # queue ids that match nothing: irrelevant with one home
    second = await w.connect("10.0.2.2", 0x05060708)
    assert second.home_id == HOUSE and first.home_id == HOUSE
    assert w.srv.get_dev_tcp_pool_sync(HOUSE) == w.srv.get_dev_tcp_pool_sync() == [first, second]

    # state is applied straight away (nothing held back)
    with caplog.at_level(logging.WARNING):
        await w.feed(first, mesh_info_73(first.queue_id, [(1, 53, 1, 20), (2, 0, 1, 30)]))
    assert w.reg.get_device(HOUSE, 2).entities[0].brightness == 30 and first.node is w.reg.get_device(HOUSE, 1)
    assert "Could not work out" not in caplog.text

    for wr in w.writers.values():
        wr.sent.clear()
    await w.command("100000002-5", b"ON")
    sent = {ip: wr.control_packets() for ip, wr in w.writers.items()}
    assert sum(len(p) for p in sent.values()) == min(device_mod.CYNC_CMD_BROADCASTS, 2)
    for ip, pkts in sent.items():
        s = w.srv.tcp_connections[ip]
        for pkt in pkts:
            # byte for byte what the single-home code built: outer 0x73 with this bridge's queue id, target 5
            inner = PacketBuilder.build_control_packet(pkt[13], 5, 0, 0xD0, 0x0D, bytes([0x11, 0x02, 0x01, 0, 0]))
            assert pkt == PacketBuilder.build_outer_packet(0x73, s.queue_id, inner)


# =====================================================================================================================
# MITM switches: one per bridge, also when two homes' bridges have the same mesh id
async def test_mitm_switches_of_same_id_bridges_in_two_homes_both_survive_rediscovery(world):
    cabin = await world.connect("10.0.1.1", CABIN)
    barn = await world.connect("10.0.3.1", BARN)
    # both bridges are mesh device 1 of their home
    await world.feed(cabin, mesh_info_73(cabin.queue_id, [(1, 137, 1, 10)]))
    await world.feed(barn, mesh_info_73(barn.queue_id, [(1, 137, 1, 10)]))
    assert cabin.node is world.reg.get_device(CABIN, 1) and barn.node is world.reg.get_device(BARN, 1)
    world.broker.published.clear()
    # a discovery replay (MQTT reconnect / HA birth) re-announces the MITM switch of every connected bridge
    await _run_discovery(world)
    switches = {t for t, p in world.broker.published if t.endswith("_mitm_mode/config") and p}
    assert switches == {
        f"{world.mqtt.ha_topic}/switch/{CABIN}_1_mitm_mode/config",
        f"{world.mqtt.ha_topic}/switch/{BARN}_1_mitm_mode/config",
    }
    # removing one bridge's switch leaves the other home's one alone
    await world.mqtt.remove_mitm_button(cabin.node)
    world.broker.published.clear()
    await _run_discovery(world)
    switches = {t for t, p in world.broker.published if t.endswith("_mitm_mode/config") and p}
    assert switches == {f"{world.mqtt.ha_topic}/switch/{BARN}_1_mitm_mode/config"}


@pytest.mark.parametrize("home", [CABIN, HOUSE, BARN])
async def test_every_home_resolves_by_its_own_queue_id(world, home):
    s = await world.connect("10.0.5.5", home)
    assert s.home_id == home
    assert [h for h in SIZES if s in world.srv.get_dev_tcp_pool_sync(h)] == [home]


# =====================================================================================================================
# 9. review fixes and findings from the first multi-home hardware run (2026-11-04, 4 homes / 105 devices)
def _with_switch_ids(**by_home) -> dict:
    """The fixture config with ``switch_id`` set on some devices: by_home = {"House": {2: 300000222}, ...}."""
    cfg = raw_cfg()
    for home, devs in by_home.items():
        for dev_id, switch_id in devs.items():
            cfg["exported_homes"][home]["devices"][dev_id]["switch_id"] = switch_id
    return cfg


async def test_status_ids_of_an_unplaced_bridge_are_not_home_evidence(world):
    """
    A 0x83 status can carry an id that is no device of the bridge's home (a group/room id, a device added after the
    export). Counted as fingerprint evidence it never goes away, so one such id could stop the bridge's real home from
    ever fitting. Only mesh-info pages (the bridge's own list of its mesh) count.
    """
    s = await world.connect("10.0.1.8", UNMATCHED_QID)
    before = world.snapshot()
    await world.feed(s, status_83(s.queue_id, 12))  # 12 is not a Cabin id
    assert s.home.candidates is None  # no evidence taken from a status packet
    assert world.snapshot() == before  # and nothing applied, the home is still unknown


async def test_only_the_first_record_of_a_mesh_reply_is_the_bridge(world, caplog):
    """The bridge's own record is the first record of a reply, not the first record of every page."""
    s = await world.connect("10.0.2.4", HOUSE)
    with caplog.at_level(logging.WARNING):
        await world.feed(s, mesh_info_73(s.queue_id, [(4, 53, 1, 40)], total=3))
        await world.feed(s, mesh_info_73(s.queue_id, [(5, 0, 1, 50), (6, 0, 1, 60)], total=3))  # page 2 of 2
    assert s.node is world.reg.get_device(HOUSE, 4)
    assert s.name == world.reg.get_device(HOUSE, 4).name
    assert "MISMATCH" not in caplog.text
    assert world.reg.get_device(HOUSE, 6).entities[0].brightness == 60  # page 2 was still applied


async def test_switch_id_names_the_bridge_device_at_hello(make_world):
    """The queue id is the device's own switchID, so the 0x23 already says which device the bridge is."""
    w = await make_world(_with_switch_ids(House={2: 300000222}))
    s = await w.connect("10.0.2.2", 300000222)
    dev = w.reg.get_device(HOUSE, 2)
    assert s.node is dev and dev.tcp_session is s


async def test_another_device_reusing_a_bridge_ip_does_not_keep_the_old_device(make_world):
    """
    A same-IP reconnect reuses the session object. When DHCP gave that IP to a device of another home, the home is
    worked out again and the session must not keep the old home's device (MITM switch, own-session commands).
    """
    w = await make_world(_with_switch_ids(House={2: 300000222}, Barn={5: 300000355}))
    s = await w.connect("10.0.7.7", 300000222)
    house_2 = w.reg.get_device(HOUSE, 2)
    assert s.node is house_2
    s2 = await w.connect("10.0.7.7", 300000355)  # another device, same IP
    assert s2 is s
    assert s2.home_id == BARN and s2.node is w.reg.get_device(BARN, 5)
    assert house_2.tcp_session is None
    # House-2's HA "MITM mode" switch is removed (empty retained config), Barn-5 gets one
    assert (f"{w.mqtt.ha_topic}/switch/{HOUSE}_2_mitm_mode/config", b"") in w.broker.published
    assert any(t == f"{w.mqtt.ha_topic}/switch/{BARN}_5_mitm_mode/config" and pl for t, pl in w.broker.published)


async def test_dropped_commands_warn_once_per_outage(world, caplog):
    def drop_warnings():
        return [
            r for r in caplog.records
            if r.levelno == logging.WARNING and "no TCP bridge connected for Cync home 'Cabin'" in r.getMessage()
        ]

    with caplog.at_level(logging.DEBUG):
        for _ in range(3):  # e.g. a dimmer slider while the bridge reconnects
            await world.command("100000001-2", b"ON")
    assert len(drop_warnings()) == 1
    # a Cabin bridge comes and goes: the next outage warns again
    s = await world.connect("10.0.1.1", CABIN)
    await s.close()
    with caplog.at_level(logging.DEBUG):
        await world.command("100000001-2", b"ON")
    assert len(drop_warnings()) == 2


async def test_queue_id_line_is_debug_on_a_single_home(make_world, caplog):
    w = await make_world(only_homes(raw_cfg(), "House"))
    with caplog.at_level(logging.INFO):
        await w.connect("10.0.2.3", UNMATCHED_QID)
    assert "0x23 queue id" not in caplog.text
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        await w.connect("10.0.2.4", UNMATCHED_QID)
    assert "0x23 queue id" in caplog.text


# ---- per-home connection cap: CYNC_MAX_TCP_CONN counts per home when there are several
@pytest.fixture
def cap(monkeypatch):
    from cync_lan.devices import proxy as proxy_mod

    monkeypatch.setattr(proxy_mod, "TCP_BLACKHOLE_DELAY", 0)

    def set_cap(n: int):
        monkeypatch.setattr(proxy_mod, "CYNC_MAX_TCP_CONN", n)

    return set_cap


async def test_connection_cap_counts_per_home(world, cap):
    """Seen on hardware: a shared cap filled with one home's devices left another home without any bridge."""
    cap(1)
    cabin = await world.connect("10.0.1.1", CABIN)
    second_cabin = await world.connect("10.0.1.2", CABIN)
    house = await world.connect("10.0.2.1", HOUSE)
    assert cabin.allowed_to_connect and house.allowed_to_connect
    assert not second_cabin.allowed_to_connect
    assert world.srv.get_dev_tcp_pool_sync(HOUSE) == [house]


async def test_bridges_whose_home_is_not_known_are_bounded_by_the_total(world, cap):
    cap(1)  # 3 homes: unplaced bridges are admitted while all bridges together are fewer than 3
    unplaced = [await world.connect(f"10.0.9.{n}", UNMATCHED_QID) for n in range(1, 5)]
    assert [u.allowed_to_connect for u in unplaced] == [True, True, True, False]
    barn = await world.connect("10.0.3.1", BARN)
    assert barn.allowed_to_connect  # a placed bridge counts only against its own home


async def test_single_home_cap_is_unchanged(make_world, cap):
    w = await make_world(only_homes(raw_cfg(), "House"))
    cap(1)
    a = await w.connect("10.0.2.1", UNMATCHED_QID)
    b = await w.connect("10.0.2.2", HOUSE)
    assert a.allowed_to_connect and not b.allowed_to_connect


async def test_unplaced_bridges_that_get_placed_later_still_count_toward_a_total(world, cap):
    """
    Without switch_ids every bridge starts unplaced and is placed by fingerprint a moment later, freeing its slot in the
    unplaced pool. Unplaced admissions are therefore bounded by CYNC_MAX_TCP_CONN x homes over ALL bridges, or one home
    would collect any number of bridges (review finding, a regression against the old total limit).
    """
    cap(1)  # 3 homes -> at most 3 bridges admitted while their home is unknown
    barn_mesh = [(3, 53, 1, 30)] + [(i, 0, 1, 40) for i in range(1, 21) if i != 3]
    placed = []
    for n in range(3):
        s = await world.connect(f"10.0.3.{10 + n}", UNMATCHED_QID)
        assert s.allowed_to_connect, n
        await world.feed(s, mesh_info_73(s.queue_id, barn_mesh, total=20))
        assert s.home_id == BARN
        placed.append(s)
    late = await world.connect("10.0.3.20", UNMATCHED_QID)
    assert not late.allowed_to_connect
    assert len(world.srv.get_dev_tcp_pool_sync(BARN)) == 3


async def test_retained_mitm_probe_does_not_hold_up_the_session(make_world):
    """The retained-state lookup can take seconds (a broker round trip): it runs as a task, not in the packet loop."""
    w = await make_world(_with_switch_ids(House={2: 300000222}))
    release = asyncio.Event()

    async def slow_probe(topic):
        await release.wait()
        return None

    w.mqtt.get_startup_topic_state = slow_probe
    s = await asyncio.wait_for(w.connect("10.0.2.2", 300000222), timeout=2)
    assert s.tasks.mitm_probe is not None and not s.tasks.mitm_probe.done()
    await s.close()
    assert s.tasks.mitm_probe.done()  # cancelled with the session
