from cync_lan.packet import (
    Parsed73ControlAck,
    Parsed83BulkStatus,
    Parsed83DeviceState,
    escape_inner_frame,
    parse_73_control_ack,
    parse_83_bulk_status,
    parse_83_device_state,
    parse_inner_frame,
    parse_outer_packet,
)


def _build_inner_frame(
    *,
    sequence: int,
    direction: int,
    opcode: int,
    arguments: bytes,
    escape: bool = True,
) -> bytes:
    seq = sequence.to_bytes(4, "little")
    command = bytes([opcode]) + len(arguments).to_bytes(2, "little") + arguments
    checksum = (sum(command) % 256).to_bytes(1, "little")
    body = seq + bytes([direction]) + command + checksum
    if escape:
        body = escape_inner_frame(body)
    return b"\x7e" + body + b"\x7e"


def test_parse_outer_packet_valid() -> None:
    packet = bytes.fromhex("730000000701020304050607")
    parsed = parse_outer_packet(packet)

    assert parsed.packet_type == 0x73
    assert parsed.packet_length == 7
    assert parsed.queue_id == b"\x01\x02\x03\x04"
    assert parsed.msg_id == b"\x05\x06\x07"
    assert parsed.payload == b""


def test_parse_outer_packet_invalid_length() -> None:
    packet = bytes.fromhex("730000000801020304050607")

    try:
        parse_outer_packet(packet)
    except ValueError as exc:
        assert "Expected: 8, got: 7" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid outer length")


def test_parse_inner_frame_unescapes_7e() -> None:
    inner = _build_inner_frame(
        sequence=1,
        direction=0xF9,
        opcode=0xD0,
        arguments=b"\x7e\x01",
    )

    parsed = parse_inner_frame(inner)
    assert parsed.arguments == b"\x7e\x01"


def test_parse_inner_frame_invalid_checksum() -> None:
    bad = bytearray(_build_inner_frame(sequence=1, direction=0xF9, opcode=0xD0, arguments=b"\x01"))
    bad[-2] ^= 0x01

    try:
        parse_inner_frame(bytes(bad))
    except ValueError as exc:
        assert "Invalid checksum" in str(exc)
    else:
        raise AssertionError("Expected ValueError for bad checksum")


def test_parse_inner_frame_malformed_escaping() -> None:
    bad = b"\x7e\x01\x02\x7d\x7e"

    try:
        parse_inner_frame(bad)
    except ValueError as exc:
        assert "Malformed escaping" in str(exc)
    else:
        raise AssertionError("Expected ValueError for malformed escaping")


def test_parse_inner_frame_malformed_boundaries() -> None:
    bad = b"\x00\x01\x02\x03\x04"

    try:
        parse_inner_frame(bad)
    except ValueError as exc:
        assert "Malformed boundaries" in str(exc)
    else:
        raise AssertionError("Expected ValueError for malformed boundaries")


def test_parse_83_device_state_direct_device_case() -> None:
    arguments = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x2A,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x01,
            0x64,
            0x32,
            0x0A,
            0x14,
            0x1E,
            0x00,
            0x00,
        ]
    )
    frame = _build_inner_frame(
        sequence=9,
        direction=0xFA,
        opcode=0xDB,
        arguments=arguments,
    )

    parsed = parse_83_device_state(frame)
    assert isinstance(parsed, Parsed83DeviceState)
    assert parsed.dev_id == 0x2A
    assert parsed.power == 0x01
    assert parsed.brightness == 0x64


def test_parse_83_bulk_status_direct_device_case() -> None:
    arguments = bytes(
        [
            0x00,
            0x02,
            0x10,
            0x01,
            0x03,
            0x64,
            0x11,
            0x02,
            0x04,
            0x00,
        ]
    )
    frame = _build_inner_frame(
        sequence=10,
        direction=0xFA,
        opcode=0xD9,
        arguments=arguments,
    )

    parsed = parse_83_bulk_status(frame)
    assert isinstance(parsed, Parsed83BulkStatus)
    assert len(parsed.devices) == 2
    assert parsed.devices[0].node_id == 0x10
    assert parsed.devices[1].sub_id == 0x02


def test_parse_73_control_ack_sol_opcode() -> None:
    frame = _build_inner_frame(
        sequence=0x2A,
        direction=0xF9,
        opcode=0xD2,
        arguments=b"\x01",
    )

    parsed = parse_73_control_ack(frame)
    assert isinstance(parsed, Parsed73ControlAck)
    assert parsed.msg_id == 0x2A
    assert parsed.opcode == 0xD2
    assert parsed.success is True
