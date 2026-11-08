"""The debug log of a device hello (0x23) must not print the device's auth code. All bytes below are fake."""

from cync_lan.utils import hello_23_hex_redacted

QID = bytes.fromhex("0a 0b 0c 0d")
AUTH = b"0123456789abcdef"  # 16 ASCII chars, like a real auth code
HELLO = bytes([0x23, 0x00, 0x00, 0x00, 0x1A, 0x03]) + QID + b"\x00\x10" + AUTH + b"\x00\x00\x3c"


def test_everything_after_the_queue_id_and_length_is_redacted():
    """The auth code layout is only inferred, so nothing after byte 11 is trusted: all of it is redacted."""
    out = hello_23_hex_redacted(HELLO)
    assert out.startswith("23 00 00 00 1a 03 0a 0b 0c 0d 00 10 ")
    assert "30 31 32" not in out and "61 62" not in out
    assert out.split(" ")[12:] == ["xx"] * (len(HELLO) - 12)


def test_a_wrong_length_byte_does_not_leak_anything():
    bad = HELLO[:11] + b"\x02" + HELLO[12:]  # declares 2 auth bytes, has 16
    out = hello_23_hex_redacted(bad)
    assert "30 31 32" not in out and out.count("xx") == len(bad) - 12


def test_short_packet_does_not_raise():
    assert hello_23_hex_redacted(HELLO[:8]).startswith("23 00")
