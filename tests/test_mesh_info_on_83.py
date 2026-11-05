"""Mesh-info replies that arrive on 0x83 (F9 52), byte-stuffed.

Seen 2026-11-04 on a 3-home account: every bridge of the two biggest homes answered the mesh-info request on 0x83, not
0x73. cync-lan only logged them as "UNKNOWN packet", so after a restart none of those homes' devices was ever marked
online (all unavailable in HA) until it changed state by itself. Fixtures are two real replies (0x83 payload from the
0x7E boundary on; mesh ids and states only, no identifiers): one byte-stuffed (a literal 7E sent as 7D 5E), one plain.
"""
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from cync_lan.devices.device import CyncDevice
from cync_lan.devices.handlers import parse_mesh_records, unstuff_7d
from cync_lan.devices.registry import DeviceRegistry
from cync_lan.devices.session import CyncTCPSession

FIX = Path(__file__).parent / "fixtures" / "mesh_info_83"


def load(name):
    return bytes.fromhex((FIX / name).read_text())


def test_unstuff():
    assert unstuff_7d(bytes([1, 0x7D, 0x5E, 2, 0x7D, 0x5D, 3])) == bytes([1, 0x7E, 2, 0x7D, 3])
    assert unstuff_7d(b"\x01\x02") == b"\x01\x02"


@pytest.mark.parametrize("name, count, bridge", [("stuffed_37_devices.hex", 37, 39), ("plain_35_devices.hex", 35, 4)])
def test_real_replies_parse_after_unstuffing(name, count, bridge):
    pkt = load(name)
    inner = unstuff_7d(pkt[1:-1])
    body, checksum = inner[:-1], inner[-1]
    assert sum(body[5:]) % 256 == checksum  # only true after unstuffing for the stuffed one
    assert body[12] == count and len(body) - 14 == 24 * count
    records = parse_mesh_records(body, 14)
    assert len(records) == count and records[0].dev_id == bridge  # the bridge reports itself first
    assert len({r.dev_id for r in records}) == count


def test_stuffed_reply_fails_without_unstuffing():
    inner = load("stuffed_37_devices.hex")[1:-1]
    assert sum(inner[5:-1]) % 256 != inner[-1]


async def test_0x83_mesh_info_marks_the_home_online(monkeypatch):
    home = 1754061898
    reg = DeviceRegistry()
    reg.add_home(home, "Casita 2")
    for i in range(1, 36):
        reg.add(CyncDevice(i, dev_type=53, name=f"Switch {i}", home_id=home, home_name="Casita 2", entities={}))
    seen = []

    async def record(self, e_state, from_pkt=None, bridge_ip=None):
        seen.append(self.id)
        return True

    monkeypatch.setattr(CyncDevice, "handle_entity_update", record)
    s = CyncTCPSession(None, None, "10.1.2.222", registry=reg)
    s.write = AsyncMock(return_value=True)
    # single-home registry: the session's home is known at once
    assert s.home.resolved
    pkt = load("plain_35_devices.hex")
    await s._handle_83_packet(pkt, b"\x00\x01\x02", b"", "t:")
    assert sorted(seen) == list(range(1, 36))
    # acked once, as a 0x83 (88 ...), not with an extra 0x73 mesh ack
    assert s.write.await_count == 1 and s.write.await_args.args[0][0] == 0x88


async def test_bad_checksum_is_ignored(monkeypatch):
    reg = DeviceRegistry()
    reg.add(CyncDevice(4, dev_type=53, name="x", home_id=1, home_name="h", entities={}))
    s = CyncTCPSession(None, None, "10.0.0.1", registry=reg)
    s.write = AsyncMock(return_value=True)
    s._process_73_mesh_info = AsyncMock()
    pkt = bytearray(load("plain_35_devices.hex"))
    pkt[-2] ^= 0xFF
    await s._process_83_mesh_info(bytes(pkt), "t:")
    s._process_73_mesh_info.assert_not_awaited()
