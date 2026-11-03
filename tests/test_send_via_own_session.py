"""A command for a device that has its own TCP session always goes through that session.

send_command() picked CYNC_CMD_BROADCASTS random bridges, so a command for a device with its own connection usually went out
through other bridges and was relayed over the BLE mesh. A deviceType 171 Full Color A19 ACKed relayed show commands but never
ran them (power, brightness and color survived the relay); sent down its own connection, the same command ran every show.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

from cync_lan.devices import device as device_mod
from cync_lan.structs import ControlMessageCallback


def bridge(name):
    return SimpleNamespace(
        name=name, ready_to_control=True, mitm_mode=False, queue_id=b"\x00\x00\x00\x01", ip_address=name,
        node=SimpleNamespace(id=0), messages=SimpleNamespace(control={}), write=AsyncMock(),
        get_ctrl_msg_id_bytes=lambda: [0x05],
    )


async def test_command_always_goes_through_the_targets_own_session(monkeypatch):
    others = [bridge(f"b{i}") for i in range(4)]
    own = bridge("own")
    pool = others[:2] + [own] + others[2:]
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=pool)))
    target = SimpleNamespace(id=4, tcp_session=own)
    for _ in range(20):
        cb = ControlMessageCallback(msg_id=0, message=None, sent_at=0.0, callback=None)
        await device_mod.CyncDevice.send_command(target, 0xE2, 0x0E, 0, bytes([0x11, 0x02, 0x07, 1, 2, 0x7A]), cb, "t:")
    assert own.write.await_count == 20
    # still a broadcast: the other slot(s) went to the other bridges
    assert sum(b.write.await_count for b in others) == 20 * (device_mod.CYNC_CMD_BROADCASTS - 1)


async def test_device_without_own_session_still_uses_random_bridges(monkeypatch):
    pool = [bridge(f"b{i}") for i in range(4)]
    monkeypatch.setattr(device_mod.g, "ncync_server", SimpleNamespace(get_dev_tcp_pool=AsyncMock(return_value=pool)))
    target = SimpleNamespace(id=7, tcp_session=None)
    cb = ControlMessageCallback(msg_id=0, message=None, sent_at=0.0, callback=None)
    await device_mod.CyncDevice.send_command(target, 0xD0, 0x0D, 0, bytes([0x11, 0x02, 0x01, 0, 0]), cb, "t:")
    assert sum(b.write.await_count for b in pool) == min(device_mod.CYNC_CMD_BROADCASTS, len(pool))
