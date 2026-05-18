from __future__ import annotations

from cync_lan.const import DATA_BOUNDARY


def require_exact_length(name: str, data: bytes, expected_len: int) -> None:
    if len(data) != expected_len:
        raise ValueError(
            f"{name} must be exactly {expected_len} bytes, got {len(data)}"
        )


def require_u8(name: str, value: int) -> None:
    if not isinstance(value, int) or not (0 <= value <= 0xFF):
        raise ValueError(f"{name} must be an integer between 0 and 255, got {value!r}")


def checksum8(data: bytes) -> int:
    return sum(data) % 256


def verify_checksum8(data: bytes, expected: int) -> bool:
    require_u8("expected", expected)
    return checksum8(data) == expected


def escape_inner_frame(data: bytes) -> bytes:
    escaped = data.replace(b"\x7d", b"\x7d\x5d")
    return escaped.replace(bytes([DATA_BOUNDARY]), b"\x7d\x5e")


def unescape_inner_frame(data: bytes) -> bytes:
    out = bytearray()
    idx = 0
    while idx < len(data):
        current = data[idx]
        if current != 0x7D:
            out.append(current)
            idx += 1
            continue

        if idx + 1 >= len(data):
            raise ValueError("Malformed escaping: dangling 0x7D in inner frame")

        nxt = data[idx + 1]
        if nxt == 0x5E:
            out.append(DATA_BOUNDARY)
        elif nxt == 0x5D:
            out.append(0x7D)
        else:
            raise ValueError(
                f"Malformed escaping: unsupported sequence 0x7D 0x{nxt:02X}"
            )
        idx += 2

    return bytes(out)


def validate_boundary_frame(frame: bytes) -> bytes:
    if len(frame) < 2:
        raise ValueError("Inner frame is too short")
    if frame[0] != DATA_BOUNDARY or frame[-1] != DATA_BOUNDARY:
        raise ValueError("Malformed boundaries for inner frame")
    return frame[1:-1]
