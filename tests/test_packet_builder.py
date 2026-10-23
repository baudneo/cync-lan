"""Characterization tests: pin the exact bytes PacketBuilder produces today."""

import pytest

from cync_lan.packet.builder import PacketBuilder as PB
from cync_lan.packet.framer import PacketFramer

QID = bytes([0x39, 0x87, 0xC8, 0x57])
MID = bytes([0x01, 0x02, 0x03])


def test_fixed_acks():
    assert PB.build_23_ack() == bytes.fromhex("28 00 00 00 02 00 00")
    assert PB.build_d3_ack() == bytes.fromhex("d8 00 00 00 00")
    assert PB.build_c3_ack() == bytes.fromhex(
        "c8 00 00 00 0b 0d 07 e8 03 0a 01 0c 04 1f fe 0c"
    )


def test_83_and_43_and_73_acks():
    assert PB.build_83_ack(MID) == bytes.fromhex("88 00 00 00 03 01 02 03")
    # 0x43 ack echoes the first two msg_id bytes and zeroes the last
    assert PB.build_43_ack(MID) == bytes.fromhex("48 00 00 00 03 01 02 00")
    assert PB.build_73_ack(QID, MID) == bytes.fromhex(
        "78 00 00 00 07 39 87 c8 57 01 02 03"
    )


def test_a3_control_request():
    assert PB.build_a3_control_request(QID, MID) == bytes.fromhex(
        "a3 00 00 00 07 39 87 c8 57 01 02 03"
    )


def test_a3_ack_shape():
    pkt = PB.build_a3_ack(QID, MID)
    assert pkt[0] == 0xAB
    assert pkt[5:9] == QID and pkt[9:12] == MID
    assert pkt[12:21] == b"xlink_dev"
    assert pkt[-4:] == bytes.fromhex("e3 4f 02 10")
    # declared length matches actual size (multiplier*256 + len + 5 header)
    assert pkt[3] * 256 + pkt[4] + 5 == len(pkt)


def test_mesh_info_request_exact():
    assert PB.build_mesh_info_request(QID) == bytes.fromhex(
        "73 00 00 00 18 39 87 c8 57 00 00 00"
        " 7e 1f 00 00 00 f8 52 06 00 00 00 ff ff 00 00 56 7e"
    )


def test_mesh_status_ack_exact():
    assert PB.build_mesh_status_ack(QID) == bytes.fromhex(
        "73 00 00 00 14 39 87 c8 57 00 00 00"
        " 7e 1e 00 00 00 f8 af 02 00 af 01 61 7e"
    )


def test_control_packet_layout_and_checksum():
    inner = PB.build_control_packet(
        msg_id=5, target_id=0x10, sub_id=0xFF, op_code=0xD0, cmd_code=0x0D,
        command_payload=b"\x01",
    )
    assert inner[0] == 0x7E and inner[-1] == 0x7E
    body = inner[1:-2]
    # checksum covers everything from byte 5 of the unbounded body to the end
    assert inner[-2] == sum(body[5:]) % 256
    assert body[0] == 5 and body[4] == 0xF8 and body[5] == 0xD0
    assert body[-2:] == bytes([0xD0, 0x01])  # op_code then payload


def test_control_packet_checksum_wraps_mod_256():
    inner = PB.build_control_packet(1, 0xFF, 0xFF, 0xFF, 0xFF, b"\xff" * 4)
    assert 0 <= inner[-2] <= 255
    assert inner[-2] == sum(inner[1:-2][5:]) % 256


def test_outer_packet_length_and_framing_roundtrip():
    inner = bytes(range(250)) * 3  # 750 bytes forces the length multiplier
    pkt = PB.build_outer_packet(0x73, QID, inner, MID)
    assert pkt[3] * 256 + pkt[4] == 4 + 3 + len(inner)
    assert PacketFramer().feed(pkt) == [pkt]


@pytest.mark.parametrize(
    "call",
    [
        lambda: PB.build_83_ack(b"\x00"),
        lambda: PB.build_73_ack(b"\x00", MID),
        lambda: PB.build_outer_packet(0x73, QID, "str"),
        lambda: PB.build_outer_packet(256, QID, b""),
        lambda: PB.build_control_packet(256, 1, 1, 1, 1, b""),
        lambda: PB.build_control_packet(1, 1, 1, 1, 1, "nope"),
    ],
)
def test_bad_inputs_rejected(call):
    with pytest.raises((ValueError, TypeError)):
        call()
