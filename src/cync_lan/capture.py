"""Record raw device traffic to disk, and load / sanitize / organize it for replay in tests.

Recording is off unless CYNC_CAPTURE_DIR is set. One file per device TCP connection, JSON lines:

    {"k":"meta","format":1,"started":"2026-...Z","ip":"10.0.0.1","app":false,"sanitized":true,"cync_lan":"0.0.8b1"}
    {"k":"rx","t":0.512,"h":"d3 00 00 00 00"}        bytes exactly as one socket read() returned them
    {"k":"tx","t":0.514,"h":"d8 00 00 00 00"}        bytes we wrote to the device
    {"k":"tx","t":9.2,"h":"73 ...","cmd":{"id":1,"name":"set_brightness","args":{"brightness":46},"target":7,"msg_id":12}}
    {"k":"ack","t":9.4,"cmd_id":1,"msg_id":12,"ok":true,"ms":212}   the device's reply to that command (ok null = none came)
    {"k":"info","t":3.1,"device_type":137,"firmware":"3.1.0","nodes":{"7":{"type":137,"endpoints":[0]}}}
    {"k":"end","t":61.0,"reason":"closed"}

rx chunk boundaries are kept, so a replay reproduces the real split / coalesced reads. Append-only, so a
crash loses at most the last few packets. Files are created 0600. Mobile-app sessions are never kept (they
carry account tokens).

Sanitizing is ON by default (CYNC_CAPTURE_SANITIZE): identifiers are replaced *before* anything is written, so
raw identifiers never reach the disk. Redactions are same-length and use recognizable markers (queue ids and
binary values -> DE AD BE EF..., text values -> SANITIZED...), so a replay still frames and parses. Two layers:
  1. structure: the queue id of every packet and the whole body of the 0x23 hello (auth code), by packet layout
  2. values: anything we can enumerate from the user's own setup (device MACs, home ids, account name/password,
     secret key, the device's IP) is searched for inside every complete packet, in the binary and text forms
Unknown fields we cannot enumerate may still hold identifiers: review a capture before publishing it.
See docs/capture.md; run `python -m cync_lan.capture --help` for the info/organize tools.
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from cync_lan.const import CYNC_LOG_NAME
from cync_lan.packet.builder import PacketBuilder

logger = logging.getLogger(CYNC_LOG_NAME)

FORMAT_VERSION = 1
SANITIZER_VERSION = 2
DEFAULT_FILE_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_DIR_MAX_BYTES = 200 * 1024 * 1024
MAX_PACKET_LEN = 8192  # same cap as PacketFramer
MIN_PATTERN_LEN = 4  # shorter values would match random bytes all the time

REDACTED_QUEUE_ID = bytes.fromhex("de ad be ef")
REDACTED_IP = "10.0.0.1"
_BIN_MARK = bytes.fromhex("de ad be ef")
_TEXT_MARK = b"SANITIZED"
# every type that appears on the wire in either direction: the device's requests plus our fixed-type replies
# (0x28 auth ack, 0xC8 connect ack, 0xD8 ping ack, 0x48 / 0x88 acks)
_VALID_HEADERS = frozenset(PacketBuilder.ALL_HEADERS) | {0x28, 0xC8, 0xD8, 0x48, 0x88}
# types whose bytes 5:9 are the device's queue id (0x23 is special-cased: it has an extra byte before it)
_QUEUE_ID_TYPES = frozenset({0x43, 0x73, 0x83, 0xA3, 0xAB, 0x78, 0x7B, 0xC3})


def _hex(data: bytes) -> str:
    return data.hex(" ")


def _cycle(mark: bytes, n: int) -> bytes:
    return (mark * (n // len(mark) + 1))[:n]


# ---------------------------------------------------------------- redaction

def _as_text(value) -> Optional[bytes]:
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text.encode("utf-8") if len(text) >= MIN_PATTERN_LEN else None


def pii_patterns(
    *,
    macs: Iterable[str] = (),
    home_ids: Iterable = (),
    secrets: Iterable = (),
    ips: Iterable[str] = (),
) -> List[Tuple[str, bytes, bool]]:
    """Search patterns for values we can enumerate. Each is (label, bytes, is_text).

    - macs: binary (both byte orders) and the usual text spellings
    - home_ids: decimal text and 4-byte big/little endian integers
    - secrets: account name / password / secret keys, as text
    - ips: dotted text and packed 4 bytes
    """
    out: dict = {}

    def add(label: str, pat: bytes, is_text: bool) -> None:
        if len(pat) >= MIN_PATTERN_LEN:
            out.setdefault(pat, (label, pat, is_text))

    for mac in macs:
        digits = "".join(c for c in str(mac or "") if c in "0123456789abcdefABCDEF")
        if len(digits) == 12:
            raw = bytes.fromhex(digits)
            add("mac", raw, False)
            add("mac", raw[::-1], False)
            for text in (digits, digits.upper(), digits.lower()):
                add("mac", text.encode(), True)
                add("mac", ":".join(text[i : i + 2] for i in range(0, 12, 2)).encode(), True)
                add("mac", "-".join(text[i : i + 2] for i in range(0, 12, 2)).encode(), True)
    for home_id in home_ids:
        try:
            n = int(home_id)
        except (TypeError, ValueError):
            continue
        if n <= 0:
            continue
        add("home_id", str(n).encode(), True)
        if n < 2**32:
            add("home_id", n.to_bytes(4, "big"), False)
            add("home_id", n.to_bytes(4, "little"), False)
    for secret in secrets:
        text = _as_text(secret)
        if text:
            add("secret", text, True)
    for ip in ips:
        try:
            add("ip", socket.inet_aton(str(ip)), False)
            add("ip", str(ip).encode(), True)
        except OSError:
            continue
    # longest first so a MAC is not half-eaten by a shorter pattern that happens to be inside it
    return sorted(out.values(), key=lambda p: -len(p[1]))


def patterns_from_mesh_config(path, extra_secrets: Sequence = ()) -> List[Tuple[str, bytes, bool]]:
    """Patterns from the user's cync_mesh.yaml (offline sanitizing of a capture recorded with sanitizing off)."""
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    homes = raw.get("exported_homes") or raw.get("account data") or {}
    macs, home_ids, secrets = [], [], list(extra_secrets)
    for home in homes.values() if isinstance(homes, dict) else []:
        if not isinstance(home, dict):
            continue
        home_ids.append(home.get("id"))
        secrets.append(home.get("access_key"))
        secrets.append(home.get("mac"))
        macs.append(home.get("mac"))
        for dev in (home.get("devices") or {}).values():
            if isinstance(dev, dict):
                macs += [dev.get("mac"), dev.get("wifi_mac")]
    return pii_patterns(macs=macs, home_ids=home_ids, secrets=secrets)


def _fix_inner_checksum(pkt: bytearray) -> None:
    """After editing bytes inside a 0x73/0x83 packet's 0x7E-bounded body, keep its checksum valid."""
    if pkt[0] in (0x73, 0x83) and len(pkt) > 20 and pkt[12] == 0x7E and pkt[-1] == 0x7E:
        pkt[-2] = sum(pkt[18:-2]) % 256


class Redactor:
    """Same-length redaction of one packet at a time. Counts what it replaced in ``counts``."""

    def __init__(self, patterns: Sequence[Tuple[str, bytes, bool]] = ()):
        self.patterns = list(patterns)
        self.counts: Counter = Counter()

    def redact_packet(self, pkt: bytearray) -> None:
        ptype, n = pkt[0], len(pkt)
        if ptype == 0x23:
            # hello: [5]=0x03, queue id at 6:10, then the auth code (device-specific, comes from the account)
            if n >= 10:
                pkt[6:10] = REDACTED_QUEUE_ID
                self.counts["queue_ids"] += 1
            if n > 12:
                pkt[12:] = b"0" * (n - 12)
                self.counts["auth_codes"] += 1
        elif ptype in _QUEUE_ID_TYPES and n >= 9:
            pkt[5:9] = REDACTED_QUEUE_ID
            self.counts["queue_ids"] += 1
        changed = False
        body_start = 12 if ptype != 0x23 else n  # never touch the framing/queue/msg-id prefix
        for label, pat, is_text in self.patterns:
            start = body_start
            while True:
                at = pkt.find(pat, start)
                if at < 0:
                    break
                pkt[at : at + len(pat)] = _cycle(_TEXT_MARK if is_text else _BIN_MARK, len(pat))
                self.counts[label] += 1
                changed = True
                start = at + len(pat)
        if changed:
            _fix_inner_checksum(pkt)


def _packet_spans(stream: bytes) -> List[Tuple[int, int]]:
    """(start, end) of each complete packet in a stream; garbage bytes are skipped."""
    spans, i, n = [], 0, len(stream)
    while i + 5 <= n:
        if stream[i] not in _VALID_HEADERS:
            i += 1
            continue
        end = i + stream[i + 3] * 256 + stream[i + 4] + 5
        if end > n:
            break
        spans.append((i, end))
        i = end
    return spans


class _DirectionState:
    """Streaming packet tracker for one direction: bytes in, redacted bytes out (same count, in order),
    released as soon as the packet they belong to is complete."""

    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self.partial = bytearray()
        self.expected: Optional[int] = None
        self.out = bytearray()  # redacted bytes not yet handed to a record

    def feed(self, chunk: bytes) -> None:
        pending = bytearray(chunk)
        while pending:
            b = pending.pop(0)
            if not self.partial:
                if b in _VALID_HEADERS:
                    self.partial.append(b)
                else:
                    self.out.append(b)  # not a packet start: kept as-is (see module doc), but counted
                    self.redactor.counts["unrecognized_bytes_kept"] += 1
                continue
            self.partial.append(b)
            if len(self.partial) == 5:
                self.expected = self.partial[3] * 256 + self.partial[4] + 5
                if self.expected > MAX_PACKET_LEN:
                    # corrupt header: drop the first byte as garbage and rescan the rest (like PacketFramer)
                    self.out.append(self.partial[0])
                    self.redactor.counts["unrecognized_bytes_kept"] += 1
                    pending = self.partial[1:] + pending
                    self.partial.clear()
                    self.expected = None
                    continue
            if self.expected is not None and len(self.partial) == self.expected:
                self._release()

    def _release(self) -> None:
        self.redactor.redact_packet(self.partial)
        self.out += self.partial
        self.partial.clear()
        self.expected = None

    def flush(self) -> None:
        """Connection over: redact whatever partial packet is left (known offsets still apply)."""
        if self.partial:
            self._release()


# ---------------------------------------------------------------- recording

class CaptureWriter:
    """Append-only recorder for one connection. All methods are cheap and never raise into the caller."""

    def __init__(
        self,
        directory: str,
        ip: str,
        *,
        version: str = "",
        sanitize: bool = True,
        patterns: Sequence[Tuple[str, bytes, bool]] = (),
        file_max_bytes: int = DEFAULT_FILE_MAX_BYTES,
        dir_max_bytes: int = DEFAULT_DIR_MAX_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.path: Optional[Path] = None
        self._fh = None
        self._clock = clock
        self._t0 = clock()
        self._written = 0
        self._file_max = file_max_bytes
        self._capped = False
        self.sanitize = sanitize
        self._redactor = Redactor(patterns)
        self._dirs = (
            {"rx": _DirectionState(self._redactor), "tx": _DirectionState(self._redactor)} if sanitize else {}
        )
        self._queue: List[list] = []  # [t, kind, nbytes, extra] waiting for their packet to complete
        self._cmd_seq = 0
        directory_path = Path(directory)
        try:
            directory_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            used = sum(f.stat().st_size for f in directory_path.glob("*.jsonl"))
            if used >= dir_max_bytes:
                logger.warning(f"capture: {directory} is over its size cap, not recording this connection")
                return
            stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
            # sanitized names carry no IP: a short hash still tells one device's connections apart
            who = hashlib.sha256(ip.encode()).hexdigest()[:8] if sanitize else ip.replace(":", "-").replace(".", "-")
            for n in range(100):
                path = directory_path / f"{stamp}_{who}_{n}.jsonl"
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    continue
                self._fh = os.fdopen(fd, "w", encoding="utf-8")
                self.path = path
                break
        except OSError as exc:
            logger.warning(f"capture: cannot open a capture file in {directory}: {exc!r}")
            return
        self._line(
            {
                "k": "meta",
                "format": FORMAT_VERSION,
                "started": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                "ip": REDACTED_IP if sanitize else ip,
                "app": False,
                "sanitized": sanitize,
                **({"sanitizer": SANITIZER_VERSION} if sanitize else {}),
                "cync_lan": version,
            }
        )

    @property
    def active(self) -> bool:
        return self._fh is not None

    def _line(self, record: dict) -> None:
        if self._fh is None:
            return
        try:
            text = json.dumps(record, separators=(",", ":")) + "\n"
            if self._written + len(text) > self._file_max:
                if not self._capped:
                    self._capped = True
                    self._fh.write('{"k":"end","reason":"file size cap reached"}\n')
                    self._fh.flush()
                    logger.warning(f"capture: {self.path} reached its size cap, recording stopped")
                return
            self._fh.write(text)
            self._fh.flush()
            self._written += len(text)
        except (OSError, ValueError) as exc:
            logger.warning(f"capture: write failed, recording stopped: {exc!r}")
            self._fh = None

    def _t(self) -> float:
        return round(self._clock() - self._t0, 3)

    def _record(self, kind: str, data: bytes, extra: Optional[dict] = None) -> None:
        if not data or self._fh is None:
            return
        t = self._t()
        if not self.sanitize:
            self._line({"k": kind, "t": t, "h": _hex(data), **(extra or {})})
            return
        self._dirs[kind].feed(data)
        self._queue.append([t, kind, len(data), extra])
        self._drain()

    def _drain(self, force: bool = False) -> None:
        """Write queued chunks, in order, once all their bytes have been redacted."""
        if force:
            for state in self._dirs.values():
                state.flush()
        while self._queue:
            t, kind, n, extra = self._queue[0]
            state = self._dirs[kind]
            if len(state.out) < n:
                break  # its packet is still incomplete; head-of-line wait keeps the order
            chunk = bytes(state.out[:n])
            del state.out[:n]
            self._queue.pop(0)
            self._line({"k": kind, "t": t, "h": _hex(chunk), **(extra or {})})

    def rx(self, data: bytes) -> None:
        self._record("rx", data)

    def tx(self, data: bytes, cmd: Optional[dict] = None) -> None:
        """``cmd`` describes the command these bytes carry (see ``next_cmd_id``); it rides on the tx line."""
        self._record("tx", data, {"cmd": cmd} if cmd else None)

    def next_cmd_id(self) -> int:
        """Per-capture sequence number that ties a tx line to the ``ack`` record the device's reply produces."""
        self._cmd_seq += 1
        return self._cmd_seq

    def ack(self, cmd: Optional[dict], *, msg_id: int, ok: Optional[bool], **fields) -> None:
        """The device answered (``ok`` True/False) or never did (``ok`` None) for a command we sent."""
        rec = {"k": "ack", "t": self._t(), "msg_id": msg_id, "ok": ok, **fields}
        if cmd and "id" in cmd:
            rec["cmd_id"] = cmd["id"]
        self._line(rec)

    def info(self, **fields) -> None:
        clean = {k: v for k, v in fields.items() if v is not None}
        if clean:
            self._line({"k": "info", "t": self._t(), **clean})

    def close(self, reason: str = "closed") -> None:
        if self._fh is None:
            return
        if self.sanitize:
            self._drain(force=True)
            report = dict(sorted(self._redactor.counts.items()))
            self._line({"k": "sanitize_report", "redacted": report})
        self._line({"k": "end", "t": self._t(), "reason": reason})
        try:
            self._fh.close()
        except OSError:
            pass
        self._fh = None

    def discard(self) -> None:
        """Stop and delete the file (used for mobile-app sessions)."""
        path = self.path
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
        self._queue.clear()
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass


# ---------------------------------------------------------------- loading

@dataclass
class Capture:
    meta: dict = field(default_factory=dict)
    info: dict = field(default_factory=dict)  # later info records override earlier ones
    records: List[Tuple[float, str, bytes]] = field(default_factory=list)  # (t, "rx"|"tx", data)
    tags: Dict[int, dict] = field(default_factory=dict)  # records index -> extra fields on that line (tx "cmd")
    acks: List[dict] = field(default_factory=list)  # "ack" records: device replies to commands we sent
    ended: bool = False
    end_reason: str = ""
    redacted: dict = field(default_factory=dict)
    path: Optional[Path] = None

    def stream(self, direction: str) -> bytes:
        return b"".join(d for _, k, d in self.records if k == direction)

    @property
    def sanitized(self) -> bool:
        return bool(self.meta.get("sanitized"))

    @property
    def device_type(self) -> Optional[int]:
        return self.info.get("device_type")

    @property
    def firmware(self) -> Optional[str]:
        return self.info.get("firmware")

    @property
    def duration(self) -> float:
        return self.records[-1][0] if self.records else 0.0


def load_capture(path) -> Capture:
    """Parse a capture file. Tolerates a truncated last line and unknown record kinds."""
    cap = Capture(path=Path(path))
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue  # truncated by a crash
            kind = rec.get("k")
            if kind == "meta":
                cap.meta = rec
            elif kind in ("rx", "tx"):
                try:
                    cap.records.append((float(rec.get("t", 0)), kind, bytes.fromhex(rec["h"])))
                except (KeyError, ValueError):
                    continue
                if isinstance(rec.get("cmd"), dict):
                    cap.tags[len(cap.records) - 1] = {"cmd": rec["cmd"]}
            elif kind == "ack":
                cap.acks.append({k: v for k, v in rec.items() if k != "k"})
            elif kind == "info":
                cap.info.update({k: v for k, v in rec.items() if k not in ("k", "t")})
            elif kind == "sanitize_report":
                cap.redacted = rec.get("redacted", {})
            elif kind == "end":
                cap.ended = True
                cap.end_reason = rec.get("reason", "")
    return cap


def dump_capture(cap: Capture, path) -> None:
    """Write a Capture back out in the same format (used by sanitize/organize and tests)."""
    lines = [json.dumps(cap.meta or {"k": "meta", "format": FORMAT_VERSION}, separators=(",", ":"))]
    for i, (t, kind, data) in enumerate(cap.records):
        lines.append(json.dumps({"k": kind, "t": t, "h": _hex(data), **cap.tags.get(i, {})}, separators=(",", ":")))
    for ack in cap.acks:
        lines.append(json.dumps({"k": "ack", **ack}, separators=(",", ":")))
    if cap.info:
        lines.append(json.dumps({"k": "info", **cap.info}, separators=(",", ":")))
    if cap.redacted:
        lines.append(json.dumps({"k": "sanitize_report", "redacted": cap.redacted}, separators=(",", ":")))
    lines.append(json.dumps({"k": "end", "reason": cap.end_reason or "closed"}, separators=(",", ":")))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def sanitize(cap: Capture, patterns: Sequence[Tuple[str, bytes, bool]] = ()) -> Tuple[Capture, Counter]:
    """Copy of ``cap`` with identifiers redacted (offline path; live recording does this before writing).

    Idempotent: sanitizing an already sanitized capture changes nothing further. Read chunk boundaries are kept.
    """
    redactor = Redactor(patterns)
    out = Capture(
        meta=dict(cap.meta),
        info=dict(cap.info),
        ended=cap.ended,
        end_reason=cap.end_reason,
        tags=dict(cap.tags),
        acks=list(cap.acks),
    )
    if "ip" in out.meta:
        out.meta["ip"] = REDACTED_IP
    out.meta["sanitized"] = True
    out.meta["sanitizer"] = SANITIZER_VERSION
    streams = {}
    for direction in ("rx", "tx"):
        state = _DirectionState(redactor)
        state.feed(cap.stream(direction))
        state.flush()
        streams[direction] = bytes(state.out)
    offsets = {"rx": 0, "tx": 0}
    for t, kind, data in cap.records:
        a = offsets[kind]
        out.records.append((t, kind, streams[kind][a : a + len(data)]))
        offsets[kind] += len(data)
    out.redacted = dict(sorted(redactor.counts.items()))
    return out, redactor.counts


# ---------------------------------------------------------------- CLI

def summarize(cap: Capture) -> str:
    types = Counter()
    for kind in ("rx", "tx"):
        stream = cap.stream(kind)
        for start, _end in _packet_spans(stream):
            types[f"{kind}:{stream[start]:02x}"] += 1
    lines = [
        f"file:        {cap.path}",
        f"started:     {cap.meta.get('started', '?')}   cync_lan: {cap.meta.get('cync_lan', '?')}   "
        f"sanitized: {cap.sanitized}",
        f"device type: {cap.device_type}   firmware: {cap.firmware}   protocol: {cap.info.get('protocol')}",
        f"duration:    {cap.duration:.1f}s   chunks: {len(cap.records)}   ended: {cap.ended} ({cap.end_reason})",
        "packets:     " + (", ".join(f"{k}={v}" for k, v in sorted(types.items())) or "none"),
    ]
    if cap.tags or cap.acks:
        answered = sum(1 for a in cap.acks if a.get("ok"))
        lines.append(f"commands:    sent={len(cap.tags)} acked={answered} acks_seen={len(cap.acks)}")
    if cap.redacted:
        lines.append("redacted:    " + ", ".join(f"{k}={v}" for k, v in cap.redacted.items()))
    return "\n".join(lines)


def organized_name(cap: Capture) -> str:
    digest = hashlib.sha256(b"".join(d for _, _, d in cap.records)).hexdigest()[:8]
    stamp = str(cap.meta.get("started", "unknown")).replace(":", "").replace("-", "")[:15]
    return f"{stamp}_{digest}.jsonl"


def organize(
    src: Path, dst: Path, *, do_sanitize: bool = True, patterns: Sequence[Tuple[str, bytes, bool]] = ()
) -> List[Path]:
    """Copy captures into dst/type_<device type>/fw_<firmware>/..., sanitizing them on the way."""
    written = []
    for f in sorted(Path(src).glob("*.jsonl")):
        cap = load_capture(f)
        if cap.meta.get("app"):
            continue
        counts: Counter = Counter()
        if do_sanitize:
            cap, counts = sanitize(cap, patterns)
        folder = Path(dst) / f"type_{cap.device_type or 'unknown'}" / f"fw_{cap.firmware or 'unknown'}"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / organized_name(cap)
        dump_capture(cap, target)
        written.append(target)
        print(f"{f.name} -> {target}   redacted now: {dict(counts) or 'nothing more'}")
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cync_lan.capture", description="Inspect, sanitize and organize cync-lan traffic captures"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_info = sub.add_parser("info", help="summarize capture files")
    p_info.add_argument("files", nargs="+")
    p_org = sub.add_parser("organize", help="sanitize + sort captures into type_<n>/fw_<v>/ folders")
    p_org.add_argument("src")
    p_org.add_argument("dst")
    p_org.add_argument("--no-sanitize", action="store_true", help="keep identifiers (never commit the result)")
    p_org.add_argument(
        "--mesh-config",
        help="your cync_mesh.yaml: its home ids, MACs and keys are searched for and removed too "
        "(needed for captures recorded with CYNC_CAPTURE_SANITIZE=no)",
    )
    args = parser.parse_args(argv)
    if args.cmd == "info":
        for f in args.files:
            print(summarize(load_capture(f)), end="\n\n")
    else:
        patterns = patterns_from_mesh_config(args.mesh_config) if args.mesh_config else []
        organize(Path(args.src), Path(args.dst), do_sanitize=not args.no_sanitize, patterns=patterns)
        print("Review the sanitized files before committing them: unknown fields may still hold identifiers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
