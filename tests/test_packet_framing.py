import pytest

from cync_lan.packet.framer import PacketFramer


def pkt(ptype: int, payload: bytes = b"", mult: int = 0) -> bytes:
    """Build a packet: type, 2 filler bytes, multiplier, length, payload."""
    if mult:
        payload = payload.ljust(mult * 256 + len(payload), b"\x01")
    length = len(payload) - mult * 256
    return bytes([ptype, 0, 0, mult, length]) + payload


PING = pkt(0xD3)
AUTH = pkt(0x23, bytes(range(1, 27)))  # 0x1a payload, as in docs/packet_structure.md
BIG = pkt(0x73, b"\xaa" * 3, mult=2)  # 515-byte payload


def test_single_packet():
    f = PacketFramer()
    assert f.feed(AUTH) == [AUTH]
    assert f.pending == 0


def test_zero_length_payload():
    assert PacketFramer().feed(PING) == [PING]


def test_coalesced_packets():
    f = PacketFramer()
    assert f.feed(PING + AUTH + PING) == [PING, AUTH, PING]


def test_multiplier_length():
    assert len(BIG) == 5 + 515
    assert PacketFramer().feed(BIG) == [BIG]


@pytest.mark.parametrize("stream", [AUTH + PING + BIG, BIG + PING + PING + AUTH])
def test_split_at_every_offset(stream):
    expected = PacketFramer().feed(stream)
    for i in range(len(stream) + 1):
        f = PacketFramer()
        out = f.feed(stream[:i]) + f.feed(stream[i:])
        assert out == expected, f"split at {i}"
        assert f.pending == 0


def test_byte_at_a_time():
    stream = AUTH + PING + BIG
    f = PacketFramer()
    out = []
    for b in stream:
        out += f.feed(bytes([b]))
    assert out == [AUTH, PING, BIG]


def test_partial_header_is_buffered_not_dropped():
    f = PacketFramer()
    assert f.feed(AUTH[:3]) == []
    assert f.pending == 3
    assert f.feed(AUTH[3:]) == [AUTH]
    assert f.dropped_bytes == 0


def test_unknown_header_resyncs_to_next_packet():
    f = PacketFramer()
    assert f.feed(b"\xff\xfe\xfd" + AUTH) == [AUTH]
    assert f.dropped_bytes == 3
    assert f.resyncs == 1


def test_oversized_length_is_rejected_and_resyncs():
    bad = bytes([0x73, 0, 0, 0xFF, 0xFF])  # claims 65540 bytes
    f = PacketFramer(max_packet_len=1024)
    assert f.feed(bad + PING) == [PING]
    assert f.pending == 0


def test_garbage_only_does_not_grow_buffer():
    f = PacketFramer()
    assert f.feed(b"\xff" * 5000) == []
    assert f.pending == 0


def test_empty_feed():
    assert PacketFramer().feed(b"") == []
