"""Cync groups (rooms): one mesh packet to the group address instead of one packet per member.

Captured 2026-11-04 (Basement home): a room toggled in the Cync app made all 4 members report their new power in ONE
0x83 burst (same timestamp), while a Home Assistant light group of 9 lights changed over 100 ms - 1 s, one member at
a time. The group address goes in the control packet's 16-bit destination (target = low byte, sub = high byte), the same
field the cloud integration (cync_lights) fills with ``groupID.to_bytes(2, "little")`` for its room commands.
"""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from cync_lan import mqtt_client as mqtt_mod
from cync_lan.cloud_api import parse_raw_groups
from cync_lan.devices import device as device_mod
from cync_lan.devices import group as group_mod
from cync_lan.devices.group import (
    CyncGroup,
    group_uuid,
    is_group_address,
    parse_group_uuid,
)
from cync_lan.structs import EntityState
from cync_lan.utils import build_nodes

HOME = 514972078
ROOM = 0x8004  # 32772


def cfg(groups=None):
    devices = {
        i: {"name": f"Light {i}", "type": 137, "fw": "30000", "mac": "AA:BB", "wifi_mac": "CC:DD",
            "endpoints": {0: f"Light {i}"}}
        for i in (3, 4, 8, 9, 10)
    }
    home = {"id": HOME, "devices": devices}
    if groups is not None:
        home["groups"] = groups
    return {"exported_homes": {"Basement": home}}


# ---- addressing
def test_group_address_range():
    assert is_group_address(0x8000) and is_group_address(0xFFFF)
    assert not is_group_address(0x7FFF) and not is_group_address(5) and not is_group_address(True)
    with pytest.raises(ValueError):
        CyncGroup(HOME, 7, "not a group", [1])


def test_address_bytes_are_little_endian():
    assert CyncGroup(HOME, ROOM, "Rec Room", [3]).address_bytes == (0x04, 0x80)


def test_uuid_round_trip():
    assert group_uuid(HOME, ROOM) == f"{HOME}-g{ROOM}"
    assert parse_group_uuid(f"{HOME}-g{ROOM}") == (HOME, ROOM)
    assert parse_group_uuid(f"{HOME}-4") is None
    assert parse_group_uuid(f"{HOME}-4-1") is None
    assert parse_group_uuid(f"{HOME}-gx") is None


# ---- packet
def bridge():
    return SimpleNamespace(
        ready_to_control=True, mitm_mode=False, queue_id=b"\x37\x64\xe6\x89", ip_address="10.0.0.2",
        node=SimpleNamespace(id=6), messages=SimpleNamespace(control={}), write=AsyncMock(),
        get_ctrl_msg_id_bytes=lambda: [0x05],
    )


async def test_group_power_is_one_packet_to_the_group_address(monkeypatch):
    b = bridge()
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[b])))
    monkeypatch.setattr(group_mod.g, "mqtt_client", SimpleNamespace(update_entity_power=AsyncMock()))
    room = CyncGroup(HOME, ROOM, "Rec Room", [3, 4])
    await room.set_power(0)
    assert b.write.await_count == 1
    pkt = b.write.await_args.args[0]
    inner = pkt[12:]
    # 7E ctrl 000000 F8 D0 0D 00 ctrl 00000000 <dest lo> <dest hi> D0 11 02 <state> 00 00 <checksum> 7E
    assert inner[:12] == bytes([0x7E, 0x05, 0, 0, 0, 0xF8, 0xD0, 0x0D, 0x00, 0x05, 0, 0])
    assert inner[12:16] == bytes([0, 0, 0x04, 0x80])
    assert inner[16:22] == bytes([0xD0, 0x11, 0x02, 0x00, 0x00, 0x00])
    assert inner[-1] == 0x7E and inner[-2] == sum(inner[6:-2]) % 256
    # only the group's home bridges are asked
    device_mod.g.ncync_server.get_dev_tcp_pool.assert_awaited_with(HOME)


async def test_group_ack_updates_every_member(monkeypatch):
    b = bridge()
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[b])))
    upd = AsyncMock()
    monkeypatch.setattr(group_mod.g, "mqtt_client", SimpleNamespace(update_entity_power=upd))
    nodes = build_nodes(cfg({ROOM: {"name": "Rec Room", "members": [3, 4]}}))
    room = nodes.get_group(HOME, ROOM)
    await room.set_power(1)
    cb = b.messages.control[0x05]
    await cb.callback()
    assert sorted(c.args[0].id for c in upd.await_args_list) == [3, 4]
    assert all(c.args[1:] == (1, 0) for c in upd.await_args_list)


async def test_group_brightness_skips_plugs(monkeypatch):
    b = bridge()
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[b])))
    upd = AsyncMock()
    monkeypatch.setattr(group_mod.g, "mqtt_client", SimpleNamespace(update_brightness=upd))
    plug = SimpleNamespace(id=3, is_plug=True, is_fan_controller=False)
    light = SimpleNamespace(id=4, is_plug=False, is_fan_controller=False)
    room = CyncGroup(HOME, ROOM, "Rec Room", [3, 4])
    room.members = [plug, light]
    await room.set_brightness(40)
    inner = b.write.await_args.args[0][12:]
    assert inner[6] == 0xF0 and inner[16:24] == bytes([0xF0, 0x11, 0x02, 0x01, 40, 0xFF, 0xFF, 0xFF])
    await b.messages.control[0x05].callback()
    assert [c.args[0] for c in upd.await_args_list] == [light]


# ---- config
def test_config_groups_are_built_and_resolved():
    nodes = build_nodes(cfg({ROOM: {"name": "Rec Room", "members": [3, 4, 99]}, "32773": {"name": "Gym", "members": [10]}}))
    room = nodes.get_group(HOME, ROOM)
    assert room.name == "Rec Room" and [m.id for m in room.members] == [3, 4]  # 99 is not configured
    assert nodes.get_group(HOME, 32773).members[0].id == 10
    assert [gr.id for gr in nodes.groups_with(nodes.get_device(HOME, 4))] == [ROOM]
    # groups are not devices
    assert sorted(nodes) == [(HOME, i) for i in (3, 4, 8, 9, 10)]


@pytest.mark.parametrize("bad", [{5: {"name": "x", "members": [3]}}, {ROOM: {"name": "x"}}, {ROOM: "x"}, ["nope"]])
def test_bad_groups_are_dropped_not_fatal(bad):
    nodes = build_nodes(cfg(bad))
    assert nodes.groups() == [] and len(nodes) == 5


def test_config_without_groups_still_loads():
    assert build_nodes(cfg()).groups() == []


# ---- cloud export
def test_parse_raw_groups_from_cloud():
    raw = [
        {"groupID": 32772, "displayName": "Recreation Room", "deviceIDArray": [3, 4], "subgroupIDArray": [32775]},
        {"groupID": 32775, "displayName": "Bar", "deviceIDArray": [8, 9], "isSubgroup": True},
        {"groupID": 32776, "displayName": "Empty", "deviceIDArray": []},
        {"groupID": 12, "displayName": "Not a group address", "deviceIDArray": [3]},
        {"groupID": 32777, "displayName": "Gone", "deviceIDArray": [77]},
        "junk",
    ]
    out = parse_raw_groups(raw, {3, 4, 8, 9, 10})
    assert out == {
        32772: {"name": "Recreation Room", "members": [3, 4, 8, 9]},  # the room includes its sub-room
        32775: {"name": "Bar", "members": [8, 9], "subgroup": True},
    }
    assert parse_raw_groups(None, {3}) == {}


def test_exported_groups_load_back():
    groups = parse_raw_groups([{"groupID": 32772, "displayName": "Rec", "deviceIDArray": [3, 4]}], {3, 4, 8, 9, 10})
    nodes = build_nodes(cfg(groups))
    assert [m.id for m in nodes.get_group(HOME, 32772).members] == [3, 4]


# ---- state
def member(dev_id, power, bri, plug=False):
    return SimpleNamespace(id=dev_id, is_plug=plug, is_fan_controller=False, supports_temperature=False,
                           supports_rgb=False, entities={0: EntityState(dev_id=dev_id, power=power, brightness=bri)})


def test_group_state_aggregates_members():
    room = CyncGroup(HOME, ROOM, "Rec", [3, 4, 8])
    room.members = [member(3, 0, 100), member(4, 1, 40), member(8, 1, 70)]
    assert room.state() == {"state": "ON", "brightness": 70}
    room.members = [member(3, 0, 100), member(4, 0, 40)]
    assert room.state() == {"state": "OFF"}
    room.members = [member(3, 1, 0, plug=True)]
    assert room.state() == {"state": "ON"}


# ---- MQTT
@pytest.fixture
async def client(monkeypatch):
    mqtt_mod.MQTTClient._instance = None
    nodes = build_nodes(cfg({ROOM: {"name": "Rec Room", "members": [3, 4]}}))
    monkeypatch.setattr(mqtt_mod.g, "ncync_server", SimpleNamespace(node_devices=nodes))
    monkeypatch.setattr(mqtt_mod.g, "env", SimpleNamespace(app_mitm_logging=False))
    c = mqtt_mod.MQTTClient()
    c.publish = AsyncMock(return_value=True)
    yield c, nodes
    mqtt_mod.MQTTClient._instance = None


async def test_mqtt_target_resolves_a_group(client):
    c, nodes = client
    target, sub = c._parse_device_target(f"{HOME}-g{ROOM}", "t:")
    assert target is nodes.get_group(HOME, ROOM) and sub is None
    assert c._parse_device_target(f"{HOME}-g32999", "t:") == (None, None)


async def test_mqtt_on_command_goes_to_the_group(client, monkeypatch):
    c, nodes = client
    room = nodes.get_group(HOME, ROOM)
    room.set_power = AsyncMock()
    res = await c._handle_cync_set(["", "set", f"{HOME}-g{ROOM}"], b'{"state": "OFF"}', "t:")
    assert res.handled
    room.set_power.assert_awaited_once_with(0, None)


async def test_discovery_config(client):
    c, nodes = client
    tpc, conf = c.group_discovery_config(nodes.get_group(HOME, ROOM))
    assert tpc.endswith(f"/light/{HOME}_group_{ROOM}/config")
    assert conf["command_topic"].endswith(f"/set/{HOME}-g{ROOM}")
    assert conf["state_topic"].endswith(f"/status/{HOME}-g{ROOM}")
    assert conf["unique_id"] == f"{HOME}_group_{ROOM}" and conf["schema"] == "json"
    assert conf["device"]["name"] == "Rec Room" and conf["device"]["model"] == "Cync room"
    assert conf["brightness"] is True and conf["supported_color_modes"]


async def test_member_update_publishes_the_room_once(client):
    c, nodes = client
    c._connected = True
    c.client = SimpleNamespace(publish=AsyncMock())
    for dev_id in (3, 4):
        node = nodes.get_device(HOME, dev_id)
        node.entities[0].power = 1
        node.entities[0].brightness = 60
        await c.pub_entity_state(node, b'{"state": "ON"}', 0)
    tasks = list(c._group_refresh.values())
    assert len(tasks) == 1
    await tasks[0]
    room_pubs = [call for call in c.publish.await_args_list if call.args[0].endswith(f"/status/{HOME}-g{ROOM}")]
    assert len(room_pubs) == 1
    assert json.loads(room_pubs[0].args[1]) == {"state": "ON", "brightness": 60}


async def test_states_are_republished_after_discovery(client):
    """Devices marked online before discovery (0x83 mesh info arrives within a second of start) must not stay
    unavailable in HA: discovery recreates the entities, so availability and state are published again after it."""
    c, nodes = client
    c._connected = True
    c.pub_online = AsyncMock(return_value=True)
    c.parse_entity_state = AsyncMock(return_value=True)
    for node in nodes.values():
        node._online = True
    nodes.get_device(HOME, 10)._online = False  # not reported yet: its state is only the defaults
    await c._republish_states(0, "t")
    assert sorted(call.args[0].id for call in c.pub_online.await_args_list) == [3, 4, 8, 9, 10]
    assert [call.args[1] for call in c.pub_online.await_args_list].count(False) == 1
    # a device that has not reported is NOT published as off
    assert sorted(call.args[0].id for call in c.parse_entity_state.await_args_list) == [3, 4, 8, 9]
    assert any(call.args[0].endswith(f"/status/{HOME}-g{ROOM}") for call in c.publish.await_args_list)
