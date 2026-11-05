"""cync-lan local groups: groups cync-lan itself puts on the switches (not in the Cync account).

The join / leave sequence mimics what the Cync app sent (captured 2026-11-04, docs/protocol.md): to put a switch that is in
a room into a group, the app made it leave the room, join the room again with flag 0x87, then join the group with 0x00;
taking it out, leave the group and join the room again with 0x00.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from cync_lan import mqtt_client as mqtt_mod
from cync_lan.devices.registry import carry_over_bridges
from cync_lan.utils import build_nodes

HOME = 1754061898
ROOM_TOILET, ROOM_SHOWER, SUB = 32776, 32778, 32789


def cfg(local=None):
    devices = {i: {"name": f"Switch {i}", "type": 53, "endpoints": {0: f"Switch {i}"}} for i in (12, 15, 20)}
    home = {
        "id": HOME, "devices": devices,
        "groups": {
            ROOM_TOILET: {"name": "Master Toilet", "members": [15]},
            ROOM_SHOWER: {"name": "Master Shower", "members": [12]},
            SUB: {"name": "A sub-room", "members": [20], "subgroup": True},
        },
    }
    if local is not None:
        home["local_groups"] = local
    return {"exported_homes": {"Casita 2": home}}


def test_local_groups_load():
    nodes = build_nodes(cfg({0x80FE: {"name": "Master Suite", "members": [12, 15]}}))
    g = nodes.get_group(HOME, 0x80FE)
    assert g.is_local and g.name == "Master Suite" and [m.id for m in g.members] == [12, 15]
    assert nodes.room_of(nodes.get_device(HOME, 15)).id == ROOM_TOILET  # the local group is not a room


@pytest.mark.parametrize("bad_id", [ROOM_TOILET, 0x80FF, 0x8000, 0x8101, 7])
def test_bad_or_colliding_ids_are_refused(bad_id):
    nodes = build_nodes(cfg({bad_id: {"name": "x", "members": [12]}}))
    g = nodes.get_group(HOME, bad_id)
    assert g is None or not g.is_local


def test_next_local_id_counts_down():
    nodes = build_nodes(cfg({0x80FE: {"name": "x", "members": [12]}}))
    assert nodes.next_local_group_id(HOME) == 0x80FD


def test_local_groups_survive_a_re_export():
    old, new = cfg({0x80FE: {"name": "Master Suite", "members": [12]}}), cfg()
    carry_over_bridges(new, old)
    assert new["exported_homes"]["Casita 2"]["local_groups"] == {0x80FE: {"name": "Master Suite", "members": [12]}}


def recorded(nodes):
    calls = []
    for dev in nodes.values():
        async def rec(group_id, join, flag=0x00, callback=None, _d=dev):
            calls.append((_d.id, "join" if join else "leave", group_id, flag if join else None))
        dev.set_group_membership = rec
    return calls


async def test_sync_mimics_the_app():
    nodes = build_nodes(cfg({0x80FE: {"name": "Suite", "members": [15, 20]}}))
    calls = recorded(nodes)
    await nodes.get_group(HOME, 0x80FE).sync_members(nodes, pause=0)
    assert calls == [
        (15, "leave", ROOM_TOILET, None), (15, "join", ROOM_TOILET, 0x87), (15, "join", 0x80FE, 0x00),
        (20, "join", 0x80FE, 0x00),  # no room: only the group
    ]


async def test_remove_puts_the_room_flag_back_unless_another_group_remains():
    nodes = build_nodes(cfg({
        0x80FE: {"name": "Suite", "members": [15]},
        0x80FD: {"name": "Other", "members": [12]},
        0x80FC: {"name": "Both", "members": [12]},
    }))
    calls = recorded(nodes)
    await nodes.get_group(HOME, 0x80FE).remove_from_members(nodes, pause=0)
    await nodes.get_group(HOME, 0x80FD).remove_from_members(nodes, pause=0)
    assert calls == [
        (15, "leave", 0x80FE, None), (15, "join", ROOM_TOILET, 0x00),
        (12, "leave", 0x80FD, None),  # still in 0x80FC: its room keeps 0x87
    ]


async def test_exported_groups_are_never_written():
    nodes = build_nodes(cfg())
    calls = recorded(nodes)
    assert await nodes.get_group(HOME, ROOM_TOILET).sync_members(nodes, pause=0) == 0
    assert calls == []


@pytest.fixture
async def client(monkeypatch):
    mqtt_mod.MQTTClient._instance = None
    nodes = build_nodes(cfg({0x80FE: {"name": "Master Suite", "members": [12, 15]}}))
    monkeypatch.setattr(mqtt_mod.g, "ncync_server", SimpleNamespace(node_devices=nodes))
    monkeypatch.setattr(mqtt_mod.g, "env", SimpleNamespace(app_mitm_logging=False))
    c = mqtt_mod.MQTTClient()
    c.publish = AsyncMock(return_value=True)
    yield c, nodes
    mqtt_mod.MQTTClient._instance = None


async def test_buttons_and_dispatch(client):
    c, nodes = client
    group = nodes.get_group(HOME, 0x80FE)
    buttons = c.local_group_button_configs(group)
    assert [b[1]["command_topic"].rsplit("/", 1)[1] for b in buttons] == ["sync", "remove"]
    assert all(b[0].startswith(f"{c.ha_topic}/button/") for b in buttons)
    group.sync_members = AsyncMock(return_value=2)
    res = await c._handle_cync_set(["", "set", group.hass_id, "sync"], b"press", "t:")
    assert res.handled
    for t in list(c.tasks):
        await t
    group.sync_members.assert_awaited_once()
    # exported rooms have no such commands
    room = nodes.get_group(HOME, ROOM_TOILET)
    assert not (await c._handle_cync_set(["", "set", room.hass_id, "sync"], b"press", "t:")).handled
