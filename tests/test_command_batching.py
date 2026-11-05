"""Command batching: an HA light group fires one command per member at once; they should reach the mesh together.

Before: each command went to 2 bridges picked at random, so 5 rooms went out through up to 10 bridges, each relaying at
its own pace. Now commands to one home within CYNC_CMD_BATCH_MS share the same bridges and each bridge gets them in
ONE write.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from cync_lan.devices import device as device_mod
from cync_lan.devices.group import CyncGroup
from cync_lan.devices.session import CyncTCPSession

HOME = 1754061898


def bridge(name):
    s = CyncTCPSession.__new__(CyncTCPSession)
    s.ip_address = name
    s.lp = name + ":"
    s.ready_to_control = True
    s.mitm_mode = False
    s.queue_id = b"\x00\x00\x00\x01"
    s.node = SimpleNamespace(id=1)
    s.messages = SimpleNamespace(control={})
    s.write = AsyncMock(return_value=True)
    counter = iter(range(1, 255))
    s.get_ctrl_msg_id_bytes = lambda: [next(counter)]
    return s


async def test_a_burst_goes_through_the_same_bridges_in_one_write(monkeypatch):
    monkeypatch.setattr(device_mod, "CYNC_CMD_BATCH_MS", 30)
    monkeypatch.setattr(device_mod, "CYNC_CMD_BROADCASTS", 2)
    pool = [bridge(f"10.0.0.{i}") for i in range(1, 9)]
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=pool)))
    monkeypatch.setattr(device_mod.g, "mqtt_client", SimpleNamespace(update_entity_power=AsyncMock()))
    rooms = [CyncGroup(HOME, 0x8000 + i, f"Room {i}", []) for i in (0x13, 0x15, 0x0B, 0x0A, 0x08)]
    for room in rooms:  # as the MQTT receiver does: one after the other, each returning at once
        await room.set_power(0)
    assert sum(b.write.await_count for b in pool) == 0  # still collecting
    await asyncio.sleep(0.06)
    used = [b for b in pool if b.write.await_count]
    assert len(used) == 2  # the same 2 bridges for all 5 rooms
    for b in used:
        assert b.write.await_count == 1  # one write each...
        data = b.write.await_args.args[0]
        assert data.count(b"\x73\x00\x00\x00") == 5  # ...holding the 5 commands
        assert len(b.messages.control) == 5  # every command is still tracked for its ACK


async def test_a_new_burst_after_the_window_may_use_other_bridges(monkeypatch):
    monkeypatch.setattr(device_mod, "CYNC_CMD_BATCH_MS", 10)
    pool = [bridge(f"10.0.0.{i}") for i in range(1, 9)]
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=pool)))
    first = device_mod._batch_bridges(HOME, pool)
    assert first is None
    device_mod._remember_batch_bridges(HOME, pool[:2])
    assert device_mod._batch_bridges(HOME, pool) == pool[:2]
    await asyncio.sleep(0.02)
    assert device_mod._batch_bridges(HOME, pool) is None  # window over
    device_mod._remember_batch_bridges(HOME, pool[:2])
    assert device_mod._batch_bridges(HOME, pool[1:]) is None  # a bridge left the pool: pick again


async def test_own_session_and_group_membership_are_not_batched(monkeypatch):
    monkeypatch.setattr(device_mod, "CYNC_CMD_BATCH_MS", 30)
    pool = [bridge(f"10.0.0.{i}") for i in range(1, 4)]
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=pool)))
    dev = device_mod.CyncDevice(15, dev_type=53, name="x", home_id=HOME, home_name="H", entities={})
    await dev.set_group_membership(0x8008, True)  # order-sensitive, 1 bridge: written at once
    assert sum(b.write.await_count for b in pool) == 1


async def test_batching_off(monkeypatch):
    monkeypatch.setattr(device_mod, "CYNC_CMD_BATCH_MS", 0)
    pool = [bridge(f"10.0.0.{i}") for i in range(1, 4)]
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=pool)))
    monkeypatch.setattr(device_mod.g, "mqtt_client", SimpleNamespace(update_entity_power=AsyncMock()))
    await CyncGroup(HOME, 0x8013, "Room", []).set_power(1)
    assert sum(b.write.await_count for b in pool) == 2  # written at once, as before
