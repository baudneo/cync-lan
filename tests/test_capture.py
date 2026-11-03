"""Capture file format, write-time sanitizing, offline sanitizer and organizer."""

from cync_lan import capture as cap_mod
from cync_lan.capture import (
    CaptureWriter,
    dump_capture,
    load_capture,
    sanitize,
    summarize,
)

PING = bytes.fromhex("d3 00 00 00 00")
HELLO_23 = bytes.fromhex("23 00 00 00 1a 03 11 22 33 44 00 10") + b"1e07deadbeefcafef00dba5e" + b"\x00\x01"


def write_capture(tmp_path, chunks, info=None):
    w = CaptureWriter(str(tmp_path), "192.168.1.50", version="test")
    assert w.active
    for kind, data in chunks:
        (w.rx if kind == "rx" else w.tx)(data)
    if info:
        w.info(**info)
    w.close()
    return w.path


def test_writer_roundtrip_and_permissions(tmp_path):
    path = write_capture(tmp_path, [("rx", PING[:2]), ("rx", PING[2:] + PING), ("tx", b"\xd8\x00\x00\x00\x00")],
                         {"device_type": 137, "firmware": "3.1.0", "nodes": {"7": {"type": 137, "endpoints": [0]}}})
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    cap = load_capture(path)
    assert [(k, d) for _, k, d in cap.records] == [("rx", PING[:2]), ("rx", PING[2:] + PING), ("tx", b"\xd8\x00\x00\x00\x00")]
    assert cap.device_type == 137 and cap.firmware == "3.1.0" and cap.ended
    assert cap.meta["format"] == 1 and cap.meta["cync_lan"] == "test"


def test_loader_tolerates_truncated_last_line(tmp_path):
    path = write_capture(tmp_path, [("rx", PING)])
    with open(path, "a") as fh:
        fh.write('{"k":"rx","t":9,"h":"d3 00')  # crash mid-write
    assert len(load_capture(path).records) == 1


def test_writer_respects_file_cap_and_dir_cap(tmp_path):
    w = CaptureWriter(str(tmp_path), "1.2.3.4", file_max_bytes=400)
    for _ in range(50):
        w.rx(PING)
    w.close()
    assert w.path.stat().st_size <= 450
    assert "file size cap" in w.path.read_text()
    full = CaptureWriter(str(tmp_path), "1.2.3.4", dir_max_bytes=1)
    assert not full.active


def test_discard_removes_the_file(tmp_path):
    w = CaptureWriter(str(tmp_path), "1.2.3.4")
    w.rx(PING)
    w.discard()
    assert not list(tmp_path.glob("*.jsonl"))


def test_sanitize_redacts_known_identifiers_and_keeps_chunking(tmp_path):
    hello_a, hello_b = HELLO_23[:7], HELLO_23[7:]  # split inside the header on purpose
    path = write_capture(tmp_path, [("rx", hello_a), ("rx", hello_b + PING), ("tx", bytes.fromhex("28 00 00 00 02 00 00"))])
    original = load_capture(path)
    clean, counts = sanitize(original)
    assert [len(d) for _, _, d in clean.records] == [len(d) for _, _, d in original.records]
    rx = clean.stream("rx")
    assert b"1e07deadbeef" not in rx and b"\x11\x22\x33\x44" not in rx
    assert rx[6:10] == cap_mod.REDACTED_QUEUE_ID
    assert rx.endswith(PING)
    assert clean.meta["ip"] == cap_mod.REDACTED_IP and clean.meta["sanitized"] is True
    assert counts["auth_codes"] == 1


def test_organize_sorts_by_type_and_firmware(tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    write_capture(src, [("rx", PING)], {"device_type": 137, "firmware": "3.1.0"})
    write_capture(src, [("rx", PING)], {})
    out = cap_mod.organize(src, dst)
    folders = sorted(str(p.parent.relative_to(dst)) for p in out)
    assert folders == ["type_137/fw_3.1.0", "type_unknown/fw_unknown"]


# --- write-time sanitizing (default on) ---

MAC = "AA:BB:CC:DD:EE:FF"
WIFI_MAC = "11:22:33:44:55:66"
HOME_ID = 169573386


def status_packet(body: bytes) -> bytes:
    """A 0x83-shaped packet: 12-byte prefix (queue id 4, msg id 3) + 0x7E-bounded body with a valid checksum."""
    inner_len = 12 + len(body) + 2
    pkt = bytearray([0x83, 0, 0, inner_len >> 8, inner_len & 0xFF]) + b"\x01\x02\x03\x04\x00\x00\x00"
    pkt += bytearray([0x7E]) + body + bytearray([0, 0x7E])
    pkt[-2] = sum(pkt[18:-2]) % 256
    return bytes(pkt)


def patterns():
    return cap_mod.pii_patterns(macs=[MAC, WIFI_MAC], home_ids=[HOME_ID], secrets=["hunter2-secret"], ips=["192.168.1.50"])


def test_live_writer_redacts_before_writing_and_keeps_checksum(tmp_path):
    body = b"\xfa\xdb\x00\x13" + bytes.fromhex("aabbccddeeff") + HOME_ID.to_bytes(4, "big") + b"hunter2-secret" + bytes(2)
    pkt = status_packet(body)
    w = CaptureWriter(str(tmp_path), "192.168.1.50", patterns=patterns())
    w.rx(pkt[:9])  # split inside the header on purpose
    w.rx(pkt[9:])
    w.tx(HELLO_23)
    w.close()
    text = w.path.read_text()
    for secret in ("aabbccddeeff", "AA:BB", "hunter2", "169573386", "1e07deadbeef", "192.168.1.50", "192-168-1-50"):
        assert secret not in text and secret.lower() not in text, secret
    assert "192.168" not in w.path.name
    cap = load_capture(w.path)
    assert cap.sanitized and cap.meta["sanitizer"] == cap_mod.SANITIZER_VERSION
    assert [len(d) for _, k, d in cap.records if k == "rx"] == [9, len(pkt) - 9]  # chunking preserved
    out = cap.stream("rx")
    assert len(out) == len(pkt)
    assert out[5:9] == cap_mod.REDACTED_QUEUE_ID
    assert b"SANITIZED" in out  # text secret
    assert out[12] == 0x7E and out[-1] == 0x7E and out[-2] == sum(out[18:-2]) % 256  # still a valid inner packet
    assert cap.redacted["mac"] >= 1 and cap.redacted["home_id"] >= 1 and cap.redacted["secret"] == 1
    assert cap.redacted["auth_codes"] == 1


def test_writer_can_be_told_not_to_sanitize(tmp_path):
    w = CaptureWriter(str(tmp_path), "192.168.1.50", sanitize=False, patterns=patterns())
    w.rx(HELLO_23)
    w.close()
    cap = load_capture(w.path)
    assert not cap.sanitized and cap.meta["ip"] == "192.168.1.50"
    assert cap.stream("rx") == HELLO_23


def test_incomplete_packet_at_close_is_still_redacted(tmp_path):
    w = CaptureWriter(str(tmp_path), "1.2.3.4")
    w.rx(HELLO_23[:20])  # connection dies mid-packet
    w.close()
    out = load_capture(w.path).stream("rx")
    assert len(out) == 20 and out[6:10] == cap_mod.REDACTED_QUEUE_ID and b"1e07" not in out


def test_unrecognized_bytes_are_counted_not_hidden(tmp_path):
    w = CaptureWriter(str(tmp_path), "1.2.3.4")
    w.rx(b"\x01\x02" + PING)
    w.close()
    cap = load_capture(w.path)
    assert cap.redacted["unrecognized_bytes_kept"] == 2


def test_pattern_builder_ignores_too_short_and_bad_values():
    pats = cap_mod.pii_patterns(macs=["", None, "zz"], home_ids=[0, -1, "x", None], secrets=["abc", None, True], ips=["nope"])
    assert pats == []


def test_offline_sanitize_with_mesh_config(tmp_path):
    mesh = tmp_path / "mesh.yaml"
    mesh.write_text(
        "exported_homes:\n  Home:\n    id: 169573386\n    access_key: 'sekrit-access-key'\n"
        "    devices:\n      7:\n        name: Lamp\n        mac: 'AA:BB:CC:DD:EE:FF'\n"
    )
    pkt = status_packet(bytes.fromhex("aabbccddeeff") + b"sekrit-access-key")
    raw = CaptureWriter(str(tmp_path), "1.2.3.4", sanitize=False)
    raw.rx(pkt)
    raw.close()
    clean, counts = sanitize(load_capture(raw.path), cap_mod.patterns_from_mesh_config(mesh))
    assert b"sekrit" not in clean.stream("rx") and bytes.fromhex("aabbccddeeff") not in clean.stream("rx")
    assert counts["mac"] == 1 and counts["secret"] == 1


def test_sanitize_is_idempotent(tmp_path):
    path = write_capture(tmp_path, [("rx", HELLO_23), ("rx", PING)])
    once, _ = sanitize(load_capture(path))
    twice, _ = sanitize(once)
    assert once.records == twice.records


def test_our_own_replies_are_redacted_too(tmp_path):
    """tx packets carry the queue id as well (acks, control packets), and fixed replies stay untouched."""
    ack_78 = bytes.fromhex("78 00 00 00 07 11 22 33 44 aa bb cc")
    connect_ack = bytes(cap_mod.PacketBuilder.DEVICE_RESPONSE_CONNECTION_ACK)
    w = CaptureWriter(str(tmp_path), "1.2.3.4")
    w.tx(ack_78)
    w.tx(connect_ack)
    w.close()
    cap = load_capture(w.path)
    tx = [d for _, k, d in cap.records if k == "tx"]
    assert tx[0][5:9] == cap_mod.REDACTED_QUEUE_ID and tx[0][9:] == ack_78[9:]
    assert tx[1] == connect_ack
    assert "unrecognized_bytes_kept" not in cap.redacted


def test_cmd_tags_and_acks_survive_load_dump_sanitize(tmp_path):
    cap = _cap_with_command(tmp_path)
    assert cap.tags and cap.acks
    clean, _ = sanitize(cap)
    assert clean.tags == cap.tags and clean.acks == cap.acks
    dump_capture(clean, tmp_path / "out.jsonl")
    again = load_capture(tmp_path / "out.jsonl")
    assert again.tags == cap.tags and again.acks == cap.acks
    assert "commands:    sent=1 acked=1" in summarize(again)


def _cap_with_command(tmp_path):
    w = CaptureWriter(str(tmp_path), "10.0.0.1", sanitize=False)
    cid = w.next_cmd_id()
    cmd = {"id": cid, "name": "set_power", "args": {"state": 0}, "target": 7, "msg_id": 3}
    w.tx(b"\x73\x00\x00\x00\x01\x00", cmd)
    w.ack(cmd, msg_id=3, ok=True, ms=12)
    w.close()
    return load_capture(w.path)
