from cync_lan.packet import PacketBuilder


def test_build_control_packet_fixture_hex() -> None:
    packet = PacketBuilder.build_control_packet(
        msg_id=1,
        target_id=2,
        sub_id=3,
        op_code=0xD0,
        command_payload=bytes([0x11, 0x02, 0x01, 0x64, 0x00, 0x00, 0x00, 0x00]),
    )

    assert (
        packet.hex()
        == "7e01000000f8d00d0001000000000203d011020164000000002b7e"
    )


def test_build_control_packet_escapes_boundary_byte() -> None:
    packet = PacketBuilder.build_control_packet(
        msg_id=1,
        target_id=2,
        sub_id=0x7E,
        op_code=0xD0,
        command_payload=bytes([0x11, 0x02, 0x7E, 0x64, 0x00, 0x00, 0x00, 0x00]),
    )

    assert packet[0] == PacketBuilder.DATA_BOUNDARY
    assert packet[-1] == PacketBuilder.DATA_BOUNDARY
    assert b"\x7e" not in packet[1:-1]
    assert b"\x7d\x5e" in packet
    assert (
        packet.hex()
        == "7e01000000f8d00d000100000000027d5ed011027d5e6400000000237e"
    )


def test_build_outer_packet_fixture_hex() -> None:
    inner = PacketBuilder.build_control_packet(
        msg_id=1,
        target_id=2,
        sub_id=3,
        op_code=0xD0,
        command_payload=bytes([0x11, 0x02, 0x01, 0x64, 0x00, 0x00, 0x00, 0x00]),
    )

    packet = PacketBuilder.build_outer_packet(
        packet_type=0x73,
        queue_id=b"\x01\x02\x03\x04",
        msg_id=b"\x00\x00\x00",
        inner_packet=inner,
    )

    assert (
        packet.hex()
        == "7300000022010203040000007e01000000f8d00d0001000000000203d011020164000000002b7e"
    )
