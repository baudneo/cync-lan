from __future__ import annotations

import struct
from typing import Optional

from cync_lan.const import DATA_BOUNDARY

from .codec import (
    checksum8,
    unescape_inner_frame,
    validate_boundary_frame,
    verify_checksum8,
)
from .types import (
    InnerFrame,
    OuterPacket,
    Parsed43Broadcast,
    Parsed43Timestamp,
    Parsed73ControlAck,
    Parsed83BulkDevice,
    Parsed83BulkStatus,
    Parsed83DeviceState,
)


def parse_outer_packet(packet: bytes) -> OuterPacket:
    if len(packet) < 5:
        raise ValueError("Packet is too short to contain an outer header")

    packet_type = packet[0]
    declared_length = (packet[3] << 8) | packet[4]
    payload = packet[5:]

    if len(payload) != declared_length:
        raise ValueError(
            "Provided packet length did not match actual packet length. "
            f"Expected: {declared_length}, got: {len(payload)}"
        )

    queue_id = payload[:4] if len(payload) >= 4 else b""
    msg_id = payload[4:7] if len(payload) >= 7 else b""
    packet_data = payload[7:] if len(payload) >= 7 else payload

    return OuterPacket(
        packet_type=packet_type,
        packet_length=declared_length,
        queue_id=queue_id,
        msg_id=msg_id,
        payload=packet_data,
    )


def parse_inner_frame(frame: bytes) -> InnerFrame:
    inner_escaped = validate_boundary_frame(frame)
    inner = unescape_inner_frame(inner_escaped)

    if len(inner) < 9:
        raise ValueError("Inner frame is too short")

    sequence = int.from_bytes(inner[0:4], "little")
    direction = inner[4]
    opcode = inner[5]
    argument_length = int.from_bytes(inner[6:8], "little")
    arguments = inner[8:-1]
    checksum = inner[-1]

    if len(arguments) != argument_length:
        raise ValueError(
            "Declared inner argument length did not match payload size. "
            f"Expected: {argument_length}, got: {len(arguments)}"
        )

    if not verify_checksum8(inner[5:-1], checksum):
        raise ValueError("Invalid checksum for inner frame")

    return InnerFrame(
        sequence=sequence,
        direction=direction,
        opcode=opcode,
        argument_length=argument_length,
        arguments=arguments,
        checksum=checksum,
        raw_unescaped=inner,
    )


def parse_43_payload(
    packet_data: Optional[bytes],
    packet_length: int,
    version: Optional[int] = None,
) -> Optional[Parsed43Timestamp | Parsed43Broadcast]:
    if not packet_data:
        return None

    if packet_data[:2] == b"\xc7\x90":
        ts_idx = 3
        ts_end_idx = -2 if version and 30000 <= version <= 40000 else -1
        ts = packet_data[ts_idx:ts_end_idx]
        if not ts:
            return None

        timestamp = ts.decode("ascii", errors="replace")
        if timestamp and timestamp[-1] != "," and not timestamp[-1].isdigit():
            timestamp = timestamp[:-1]

        return Parsed43Timestamp(timestamp=timestamp)

    struct_len = 20 if b"\x2e" in packet_data else 19
    extractions: list[tuple[str, list[int]]] = []

    for idx in range(0, packet_length, struct_len):
        extracted = packet_data[idx : idx + struct_len]
        if len(extracted) != struct_len:
            continue
        status_struct = extracted[3:10] + b"\x01"
        extractions.append((extracted.hex(" "), list(status_struct)))

    return Parsed43Broadcast(extractions=extractions)


def parse_83_device_state(packet_data: bytes) -> Optional[Parsed83DeviceState]:
    frame = parse_inner_frame(packet_data)
    if frame.direction != 0xFA or frame.opcode != 0xDB:
        return None
    if frame.argument_length < 17:
        raise ValueError("0x83 state frame payload is too short")

    dev_id = frame.arguments[5]
    recently_seen, power, bri, tmp, red, green, blue = struct.unpack(
        ">BBBBBBB", frame.arguments[10:17]
    )

    return Parsed83DeviceState(
        dev_id=dev_id,
        recently_seen=recently_seen,
        power=power,
        brightness=bri,
        temperature=tmp,
        red=red,
        green=green,
        blue=blue,
        checksum_valid=True,
    )


def parse_83_bulk_status(packet_data: bytes) -> Optional[Parsed83BulkStatus]:
    frame = parse_inner_frame(packet_data)
    if frame.direction != 0xFA or frame.opcode != 0xD9:
        return None

    if len(frame.arguments) < 2:
        return Parsed83BulkStatus(devices=[], checksum_valid=True)

    device_count = frame.arguments[1]
    devices: list[Parsed83BulkDevice] = []
    idx = 2
    for _ in range(device_count):
        if idx + 4 > len(frame.arguments):
            break
        devices.append(
            Parsed83BulkDevice(
                node_id=frame.arguments[idx],
                sub_id=frame.arguments[idx + 1],
                status_type=frame.arguments[idx + 2],
                value=frame.arguments[idx + 3],
            )
        )
        idx += 4

    return Parsed83BulkStatus(devices=devices, checksum_valid=True)


def parse_73_inner_struct(packet_data: bytes) -> Optional[bytes]:
    if not packet_data or packet_data[0] != DATA_BOUNDARY:
        return None
    end_idx = packet_data[1:].find(DATA_BOUNDARY)
    if end_idx < 0:
        raise ValueError("Malformed boundaries for 0x73 packet")
    frame = packet_data[: end_idx + 2]
    parsed = parse_inner_frame(frame)
    return parsed.raw_unescaped


def parse_73_control_ack(packet_data: bytes) -> Optional[Parsed73ControlAck]:
    frame = parse_inner_frame(packet_data)
    if frame.direction != 0xF9 or frame.opcode not in (0xD0, 0xD2, 0xE2, 0xF0):
        return None

    success = bool(frame.argument_length and frame.arguments and frame.arguments[0] == 1)
    return Parsed73ControlAck(
        msg_id=frame.raw_unescaped[0],
        opcode=frame.opcode,
        success=success,
    )


def compute_legacy_83_checksum(packet_data: bytes) -> tuple[int, int]:
    if len(packet_data) < 3:
        raise ValueError("Packet too short for checksum")
    checksum = packet_data[-2]
    calc_checksum = checksum8(packet_data[6:-2])
    return checksum, calc_checksum
