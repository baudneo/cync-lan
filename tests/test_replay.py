"""Replay harness (tests/replay_harness.py) and every sanitized real capture under tests/captures/."""

from pathlib import Path

import pytest
from replay_harness import replay

from cync_lan.capture import CaptureWriter, load_capture

PING = bytes.fromhex("d3 00 00 00 00")
CAPTURES = Path(__file__).parent / "captures"


def write_capture(tmp_path, chunks, info=None):
    w = CaptureWriter(str(tmp_path), "192.168.1.50", version="test")
    for kind, data in chunks:
        (w.rx if kind == "rx" else w.tx)(data)
    if info:
        w.info(**info)
    w.close()
    return w.path


async def test_replay_answers_pings_and_handles_split_reads(tmp_path):
    path = write_capture(tmp_path, [("rx", PING[:2]), ("rx", PING[2:] + PING)])
    res = await replay(load_capture(path))
    assert res.packets_received == 2
    assert res.tx.count(bytes.fromhex("d8 00 00 00 00")) == 2
    assert (res.packets_failed, res.dropped_bytes, res.pending) == (0, 0, 0)


async def test_replay_survives_garbage_between_packets(tmp_path):
    path = write_capture(tmp_path, [("rx", b"\x01\x02" + PING)])
    res = await replay(load_capture(path))
    assert res.dropped_bytes == 2 and res.packets_failed == 0


async def test_replay_restores_global_state(tmp_path):
    from replay_harness import g

    before = (g.ncync_server, g.mqtt_client)
    await replay(load_capture(write_capture(tmp_path, [("rx", PING)])))
    assert (g.ncync_server, g.mqtt_client) == before


def _real_captures():
    return sorted(CAPTURES.glob("type_*/fw_*/*.jsonl")) if CAPTURES.exists() else []


@pytest.mark.parametrize("path", _real_captures(), ids=lambda p: "/".join(p.parts[-3:]))
async def test_real_capture_replays_cleanly(path):
    """Invariants every capture must keep satisfying as the code changes."""
    cap = load_capture(path)
    assert cap.sanitized, "only sanitized captures belong in the repo"
    res = await replay(cap)
    assert res.packets_failed == 0, "a handler raised on a recorded packet"
    assert res.dropped_bytes == 0, "the framer had to skip bytes it should have understood"
    assert res.pending == 0, "capture ends mid-packet (truncated capture?)"
