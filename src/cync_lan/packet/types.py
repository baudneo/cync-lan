from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class OuterPacketType(IntEnum):
    AUTH = 0x23
    APP_SYNC = 0x43
    APP_SYNC_ACK = 0x48
    MESH = 0x73
    MESH_ACK = 0x78
    STATE = 0x83
    STATE_ACK = 0x88
    CONTROL = 0xA3
    CONTROL_ACK = 0xAB
    CONNECT = 0xC3
    PING = 0xD3


class InnerDirection(IntEnum):
    REQUEST = 0xF8
    RESPONSE = 0xF9
    ANNOUNCE = 0xFA


@dataclass(frozen=True)
class OuterPacket:
    packet_type: int
    packet_length: int
    queue_id: bytes
    msg_id: bytes
    payload: bytes


@dataclass(frozen=True)
class InnerFrame:
    sequence: int
    direction: int
    opcode: int
    argument_length: int
    arguments: bytes
    checksum: int
    raw_unescaped: bytes


@dataclass(frozen=True)
class Parsed83DeviceState:
    dev_id: int
    recently_seen: int
    power: int
    brightness: int
    temperature: int
    red: int
    green: int
    blue: int
    checksum_valid: bool


@dataclass(frozen=True)
class Parsed83BulkDevice:
    node_id: int
    sub_id: int
    status_type: int
    value: int


@dataclass(frozen=True)
class Parsed83BulkStatus:
    devices: list[Parsed83BulkDevice]
    checksum_valid: bool


@dataclass(frozen=True)
class Parsed73ControlAck:
    msg_id: int
    opcode: int
    success: bool


@dataclass(frozen=True)
class Parsed43Timestamp:
    timestamp: str


@dataclass(frozen=True)
class Parsed43Broadcast:
    extractions: list[tuple[str, list[int]]]
