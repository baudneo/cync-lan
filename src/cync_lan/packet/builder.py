from __future__ import annotations

import struct

from cync_lan.const import DATA_BOUNDARY

from .codec import checksum8, escape_inner_frame, require_exact_length, require_u8


class PacketBuilder:
    DATA_BOUNDARY = DATA_BOUNDARY

    # Phone app packet families
    APP_AUTH_HEADER = (0x13, 0x00, 0x00, 0x00)
    # app and device both use A3, so dont depend on it for app/device ID
    APP_CONNECT_HEADER = (0xA3, 0x00, 0x00, 0x00)
    APP_REQUEST_HEADERS = (0x13,)
    APP_AUTH_RESPONSE = (0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
    APP_RESPONSE_HEADERS = (0x18,)
    APP_HEADERS = APP_REQUEST_HEADERS + APP_RESPONSE_HEADERS

    # Device packet families
    DEVICE_REQUEST_X23 = (0x23,)
    DEVICE_REQUEST_XC3 = (0xC3,)
    DEVICE_REQUEST_XD3 = (0xD3,)
    DEVICE_REQUEST_X83 = (0x83,)
    DEVICE_REQUEST_X73 = (0x73,)
    DEVICE_REQUEST_X7B = (0x7B,)
    DEVICE_REQUEST_X43 = (0x43,)
    DEVICE_REQUEST_XA3 = (0xA3,)
    DEVICE_REQUEST_XAB = (0xAB,)
    DEVICE_REQUEST_HEADERS = (0x23, 0xC3, 0xD3, 0x83, 0x73, 0x7B, 0x43, 0xA3, 0xAB)

    DEVICE_RESPONSE_AUTH_ACK = (0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00)
    # todo: how is this built?
    DEVICE_RESPONSE_CONNECTION_ACK = (
        0xC8,
        0x00,
        0x00,
        0x00,
        0x0B,
        0x0D,
        0x07,
        0xE8,
        0x03,
        0x0A,
        0x01,
        0x0C,
        0x04,
        0x1F,
        0xFE,
        0x0C,
    )
    DEVICE_RESPONSE_X48_ACK = (0x48, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00)
    DEVICE_RESPONSE_X88_ACK = (0x88, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00)
    DEVICE_RESPONSE_PING_ACK = (0xD8, 0x00, 0x00, 0x00, 0x00)
    DEVICE_RESPONSE_X78_BASE = (0x78, 0x00, 0x00, 0x00)
    DEVICE_RESPONSE_X7B_BASE = (0x7B, 0x00, 0x00, 0x00)

    DEVICE_HEADERS = (0x23, 0xC3, 0xD3, 0x83, 0x73, 0x7B, 0x78, 0x43, 0xA3, 0xAB)
    ALL_HEADERS = DEVICE_HEADERS + APP_REQUEST_HEADERS + APP_RESPONSE_HEADERS

    @staticmethod
    def _require_len(name: str, data: bytes, expected_len: int) -> None:
        require_exact_length(name, data, expected_len)

    @staticmethod
    def _require_u8(name: str, value: int) -> None:
        require_u8(name, value)

    @classmethod
    def is_device_request(cls, packet_type: int) -> bool:
        return packet_type in cls.DEVICE_REQUEST_HEADERS

    @classmethod
    def is_app_request(cls, packet_type: int) -> bool:
        return packet_type in cls.APP_HEADERS

    @staticmethod
    def build_23_ack() -> bytes:
        return bytes(PacketBuilder.DEVICE_RESPONSE_AUTH_ACK)

    @staticmethod
    def build_a3_ack(queue_id: bytes, msg_id: bytes) -> bytes:
        """Respond to a 0xA3 packet from the device."""
        PacketBuilder._require_len("queue_id", queue_id, 4)
        PacketBuilder._require_len("msg_id", msg_id, 3)
        payload = b"xlink_dev" + bytes(948) + b"\xe3\x4f\x02\x10"
        total_len = len(queue_id) + len(msg_id) + len(payload)
        length_factor, length_byte = divmod(total_len, 256)
        header = b"\xab\x00\x00" + bytes([length_factor, length_byte])
        return header + queue_id + msg_id + payload

    @staticmethod
    def build_a3_control_request(queue_id: bytes, msg_id: bytes) -> bytes:
        """Build the 0xA3 packet that enables control for a device session."""
        PacketBuilder._require_len("queue_id", queue_id, 4)
        PacketBuilder._require_len("msg_id", msg_id, 3)
        return bytes([0xA3, 0x00, 0x00, 0x00, 0x07]) + queue_id + msg_id

    @staticmethod
    def build_c3_ack() -> bytes:
        return bytes(PacketBuilder.DEVICE_RESPONSE_CONNECTION_ACK)

    @staticmethod
    def build_d3_ack() -> bytes:
        return bytes(PacketBuilder.DEVICE_RESPONSE_PING_ACK)

    @staticmethod
    def build_43_ack(msg_id: bytes) -> bytes:
        """Respond to a 0x43 packet from the device."""
        PacketBuilder._require_len("msg_id", msg_id, 3)
        return bytes([0x48, 0x00, 0x00, 0x00, 0x03]) + msg_id[:-1] + b"\x00"

    @staticmethod
    def build_73_ack(queue_id: bytes, msg_id: bytes) -> bytes:
        """Respond to a 0x73 packet from the device."""
        PacketBuilder._require_len("queue_id", queue_id, 4)
        PacketBuilder._require_len("msg_id", msg_id, 3)
        return struct.pack(">BBBBB", 0x78, 0x00, 0x00, 0x00, 0x07) + queue_id + msg_id

    @staticmethod
    def build_83_ack(msg_id: bytes) -> bytes:
        """Respond to a 0x83 packet from the device."""
        PacketBuilder._require_len("msg_id", msg_id, 3)
        return bytes([0x88, 0x00, 0x00, 0x00, 0x03]) + msg_id

    @staticmethod
    def build_mesh_info_request(
        queue_id: bytes, msg_id: bytes = b"\x00\x00\x00"
    ) -> bytes:
        """Build the 0x73 request that asks a bridge for mesh status info."""
        PacketBuilder._require_len("queue_id", queue_id, 4)
        PacketBuilder._require_len("msg_id", msg_id, 3)
        inner_packet = bytes(
            [
                PacketBuilder.DATA_BOUNDARY,
                0x1F,
                0x00,
                0x00,
                0x00,
                0xF8,
                0x52,
                0x06,
                0x00,
                0x00,
                0x00,
                0xFF,
                0xFF,
                0x00,
                0x00,
                0x56,
                PacketBuilder.DATA_BOUNDARY,
            ]
        )
        return PacketBuilder.build_outer_packet(
            0x73, queue_id, inner_packet, msg_id=msg_id
        )

    @staticmethod
    def build_mesh_status_ack(
        queue_id: bytes, msg_id: bytes = b"\x00\x00\x00"
    ) -> bytes:
        """Build ACK packet sent after processing a mesh info page (0xF8 0xAF)."""
        PacketBuilder._require_len("queue_id", queue_id, 4)
        PacketBuilder._require_len("msg_id", msg_id, 3)
        inner_packet = bytes(
            [
                PacketBuilder.DATA_BOUNDARY,
                0x1E,
                0x00,
                0x00,
                0x00,
                0xF8,
                0xAF,
                0x02,
                0x00,
                0xAF,
                0x01,
                0x61,
                PacketBuilder.DATA_BOUNDARY,
            ]
        )
        return PacketBuilder.build_outer_packet(
            0x73, queue_id, inner_packet, msg_id=msg_id
        )

    @staticmethod
    def build_control_packet(
        msg_id: int,
        target_id: int,
        sub_id: int,
        op_code: int,
        command_payload: bytes,
    ) -> bytes:
        """Build an escaped 0x7E-framed inner control payload for 0x73 mesh packets."""
        PacketBuilder._require_u8("msg_id", msg_id)
        PacketBuilder._require_u8("target_id", target_id)
        PacketBuilder._require_u8("sub_id", sub_id)
        PacketBuilder._require_u8("op_code", op_code)
        if not isinstance(command_payload, bytes):
            raise TypeError(f"command_payload must be bytes, got {type(command_payload)!r}")

        header = struct.pack(">BxxxBBBB", msg_id, 0xF8, op_code, 0x0D, 0x00)
        routing = struct.pack(">BxxxxBB", msg_id, target_id, sub_id)
        inner_data = header + routing + struct.pack(">B", op_code) + command_payload

        checksum = checksum8(inner_data[5:])
        frame_body = escape_inner_frame(inner_data + struct.pack(">B", checksum))
        return struct.pack(">B", PacketBuilder.DATA_BOUNDARY) + frame_body + struct.pack(
            ">B", PacketBuilder.DATA_BOUNDARY
        )

    @staticmethod
    def build_outer_packet(
        packet_type: int,
        queue_id: bytes,
        inner_packet: bytes,
        msg_id: bytes = b"\x00\x00\x00",
    ) -> bytes:
        """Build the outer TCP packet (e.g. 0x73 commands)."""
        PacketBuilder._require_u8("packet_type", packet_type)
        PacketBuilder._require_len("queue_id", queue_id, 4)
        PacketBuilder._require_len("msg_id", msg_id, 3)
        if not isinstance(inner_packet, bytes):
            raise TypeError(f"inner_packet must be bytes, got {type(inner_packet)!r}")

        packet_length = len(queue_id) + 3 + len(inner_packet)
        length_multiplier, length_remainder = divmod(packet_length, 256)
        header = struct.pack(
            ">BBBBB", packet_type, 0x00, 0x00, length_multiplier, length_remainder
        )

        return header + queue_id + msg_id + inner_packet
