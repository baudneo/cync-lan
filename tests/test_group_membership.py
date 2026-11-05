"""Group join / leave (op 8E, inner op D7) and the device's group-list report, against packets captured 2026-11-04.

The Cync app, relayed through cync-lan's app proxy and a hybrid bridge, created and deleted a group and a room for one
switch (mesh id 15). Inner packets below are verbatim from that capture (no identifiers: the queue id is in the outer
header, which is not included).
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from cync_lan.devices import device as device_mod
from cync_lan.devices.device import CyncDevice
from cync_lan.devices.handlers import parse_group_list
from cync_lan.packet import PacketBuilder
from cync_lan.structs import ControlMessageCallback

JOIN_801A = "7e 37 00 00 00 f8 8e 0e 00 37 00 00 00 00 0f 00 d7 11 02 01 1a 80 00 67 7e"
LEAVE_8008 = "7e 36 00 00 00 f8 8e 0d 00 36 00 00 00 00 0f 00 d7 11 02 00 08 80 52 7e"
JOIN_801A_ROOM_FLAG = "7e 3e 00 00 00 f8 8e 0e 00 3e 00 00 00 00 0f 00 d7 11 02 01 1a 80 87 f5 7e"
POWER_ON = "7e 3a 00 00 00 f8 d0 0d 00 3a 00 00 00 00 0f 00 d0 11 02 01 00 00 0a 7e"
# device 15's reports (FA 8E ... D4): after joining 0x801B it is in 0x801B and 0x801A
REPORT_1B_1A = (
    "7e 3f 00 00 00 fa 8e 20 00 89 a2 16 0f 00 00 00 d4 11 02 1b 1a ff ff ff ff ff ff "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 14 7e"
)
REPORT_EMPTY = (
    "7e 3e 00 00 00 fa 8e 20 00 5a 2e 90 0f 00 00 00 d4 11 02 ff ff ff ff ff ff ff ff "
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 b4 7e"
)


def h(s):
    return bytes.fromhex(s)


@pytest.mark.parametrize("captured, payload", [
    (JOIN_801A, [0x11, 0x02, 0x01, 0x1A, 0x80, 0x00]),
    (LEAVE_8008, [0x11, 0x02, 0x00, 0x08, 0x80]),
    (JOIN_801A_ROOM_FLAG, [0x11, 0x02, 0x01, 0x1A, 0x80, 0x87]),
])
def test_builder_reproduces_the_apps_packets(captured, payload):
    cap = h(captured)
    built = PacketBuilder.build_control_packet(
        msg_id=cap[1], target_id=0x0F, sub_id=0, op_code=0x8E, cmd_code=8 + len(payload),
        command_payload=bytes(payload), inner_op=0xD7,
    )
    assert built == cap


def test_builder_unchanged_without_inner_op():
    cap = h(POWER_ON)
    built = PacketBuilder.build_control_packet(
        msg_id=0x3A, target_id=0x0F, sub_id=0, op_code=0xD0, cmd_code=0x0D, command_payload=bytes([0x11, 0x02, 1, 0, 0])
    )
    assert built == cap


def bridge(ctrl):
    return SimpleNamespace(
        ready_to_control=True, mitm_mode=False, hybrid=False, queue_id=b"\x00\x00\x00\x01", ip_address="b",
        node=SimpleNamespace(id=1), messages=SimpleNamespace(control={}), write=AsyncMock(),
        get_ctrl_msg_id_bytes=lambda: [ctrl],
    )


@pytest.mark.parametrize("join, flag, captured, ctrl", [
    (True, 0x00, JOIN_801A, 0x37), (False, 0x00, LEAVE_8008, 0x36), (True, 0x87, JOIN_801A_ROOM_FLAG, 0x3E),
])
async def test_set_group_membership_sends_the_apps_bytes(monkeypatch, join, flag, captured, ctrl):
    b = bridge(ctrl)
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[b])))
    dev = CyncDevice(15, dev_type=53, name="Master Toilet Lights", home_id=1, home_name="H", entities={})
    group = 0x801A if captured != LEAVE_8008 else 0x8008
    await dev.set_group_membership(group, join, flag)
    pkt = b.write.await_args.args[0]
    assert pkt[0] == 0x73 and pkt[12:] == h(captured)


async def test_group_ids_outside_80xx_are_refused(monkeypatch):
    b = bridge(1)
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=[b])))
    dev = CyncDevice(15, dev_type=53, name="x", home_id=1, home_name="H", entities={})
    await dev.set_group_membership(0x9001, True)
    await dev.set_group_membership(0x0005, True)
    b.write.assert_not_awaited()


def test_parse_group_list():
    assert parse_group_list(h(REPORT_1B_1A)) == (15, [0x801B, 0x801A])
    assert parse_group_list(h(REPORT_EMPTY)) == (15, [])
    assert parse_group_list(h(POWER_ON)) is None


def test_hybrid_keeps_our_group_report_from_the_cloud():
    import time

    from cync_lan.devices.session import CyncTCPSession
    from cync_lan.structs import MessageCache

    s = CyncTCPSession.__new__(CyncTCPSession)
    s.messages = MessageCache()
    report = bytes([0x73, 0, 0, 0, 0x30]) + b"\x00" * 7 + h(REPORT_1B_1A)
    s.hybrid_last_ctrl, s.hybrid_sent_at = 0x3F, time.time()
    assert s.is_own_reply(report)
    s.hybrid_last_ctrl = 0x40  # the cloud's (the app's) command, not ours
    assert not s.is_own_reply(report)


async def test_callback_is_cleared_on_the_8e_reply():
    """The F9 8E success reply (captured) pops the pending command and runs its callback, like D0 / F0 / E2."""
    from cync_lan.devices.registry import DeviceRegistry
    from cync_lan.devices.session import CyncTCPSession

    reg = DeviceRegistry()
    reg.add(CyncDevice(15, dev_type=53, name="x", home_id=1, home_name="H", entities={}))
    s = CyncTCPSession(None, None, "10.0.0.2", registry=reg)
    s.write = AsyncMock(return_value=True)
    s.queue_id = b"\x00\x00\x00\x01"
    done = AsyncMock()
    s.messages.control[0x15] = ControlMessageCallback(msg_id=0x15, message=None, sent_at=0.0, callback=done)
    await s._handle_73_mesh_control(h("7e 15 00 00 00 f9 8e 01 00 00 8f 7e"), b"", b"\x00\x97\x00", "t:")
    done.assert_awaited_once()
    assert 0x15 not in s.messages.control


async def test_group_report_is_stored_on_the_device():
    from cync_lan.devices.registry import DeviceRegistry
    from cync_lan.devices.session import CyncTCPSession

    reg = DeviceRegistry()
    dev = CyncDevice(15, dev_type=53, name="x", home_id=1, home_name="H", entities={})
    reg.add(dev)
    s = CyncTCPSession(None, None, "10.0.0.2", registry=reg)
    s.write = AsyncMock(return_value=True)
    s.queue_id = b"\x00\x00\x00\x01"
    await s._handle_73_mesh_control(h(REPORT_1B_1A), b"", b"\x00\x98\x00", "t:")
    assert dev.group_slots == [0x801B, 0x801A]
