# Recording and replaying real device traffic

cync-lan can record the raw bytes of every device connection to disk. The recordings are used two ways:
to study the protocol (see `docs/protocol.md`), and as **replay fixtures**: tests feed the recorded bytes, with
the original read boundaries, through a real `CyncTCPSession` and check nothing breaks.

## Recording
Set `CYNC_CAPTURE_DIR` (unset = off) and restart:

| env | default | meaning |
|---|---|---|
| `CYNC_CAPTURE_DIR` | unset | directory for capture files (created 0700, files 0600). In Docker use a mounted path, e.g. `/config/captures` |
| `CYNC_CAPTURE_SANITIZE` | `yes` | replace identifiers **before writing** (see below); leave it on unless you are doing private analysis |
| `CYNC_CAPTURE_FILE_MAX_MB` | 20 | one file stops recording at this size |
| `CYNC_CAPTURE_MAX_MB` | 200 | no new files are started once the directory holds this much |

One `*.jsonl` file per device TCP connection (a reconnect starts a new file). Lines are `meta` (start time, ip,
cync-lan version), `rx` (bytes as one socket read returned them), `tx` (bytes we sent), `info` (device type,
firmware, protocol version, and the configured node ids with their types and endpoint ids), `end`. Mobile-app
sessions are never kept: they carry account tokens.

### Commands and their replies

When the bridge sends a control command (power, brightness, color temperature, RGB, light show), the `tx` line
carries a `cmd` tag, and the device's reply gets its own `ack` record that points back at it:

```
{"k":"tx","t":9.2,"h":"73 00 00 00 ...","cmd":{"id":1,"name":"set_brightness","args":{"brightness":46},"target":7,"sub_id":0,"msg_id":12}}
{"k":"rx","t":9.4,"h":"73 00 00 00 ..."}
{"k":"ack","t":9.4,"cmd_id":1,"msg_id":12,"ok":true,"ms":212}
```

`cmd.id` is a per-file counter, `msg_id` is the one-byte control id we put in the packet (it rolls over at 256, so
use `cmd_id` to match). `ok` is true/false for the device's success flag, or null with `reason: "timeout"` when no
reply arrived before the stale-callback cleanup. The tag is only metadata: it never goes to the device. Replies to
commands that were not tagged (mesh info refreshes, app-issued commands) have no `ack` record. The `ack` lands
right after the `rx` chunk the reply arrived in, which may hold several packets, so match on ids rather than position.

## Sanitizing (on by default)
With `CYNC_CAPTURE_SANITIZE=yes` (the default) identifiers are replaced in memory, packet by packet, so they never
reach the disk. Replacements keep the exact length and use markers that are obviously fake, so a replay still frames,
parses and passes checksums: binary values become `DE AD BE EF` repeated, text values become `SANITIZED` repeated.

| what | how it is found | replaced with |
|---|---|---|
| queue id, in both directions (our acks and control packets carry it too) | packet layout (bytes 5:9 for 0x43/73/83/A3/AB/78/7B/C3, 6:10 for 0x23) | `de ad be ef` |
| body of the 0x23 hello (auth code) | packet layout (byte 12 to the end) | ASCII `0`s |
| device MACs (BT + Wi-Fi), as binary (both byte orders) and text | your configured devices | markers |
| home ids, as decimal text and 4-byte big/little endian | your configured devices | markers |
| account username / password, `CYNC_SECRET_KEY` | your environment | `SANITIZED...` |
| the device's own IP, packed and as text | the connection | markers |
| IP in the file header and in the file name | always | `10.0.0.1` / a short hash |

If a replacement lands inside a 0x73/0x83 inner packet its checksum is recomputed. Each file ends with a
`sanitize_report` line saying how many of each were replaced (check it: a capture that reports zero MACs from a
device with a known MAC deserves a look). `info` shows it too.

What it cannot do: remove identifiers it cannot enumerate. Bytes that are not part of a recognised packet are kept
(and counted as `unrecognized_bytes_kept`), and any unknown field inside a packet that happens to hold something
personal is not recognised. **Read a capture before you publish it**, and tell me about any identifier you find so
the rules can learn it.

With `CYNC_CAPTURE_SANITIZE=no` (or captures from before this option existed) the file holds raw identifiers: keep
it private, and sanitize it offline with your mesh config so the home id, MACs and access keys are searched for too:
`python -m cync_lan.capture organize SRC DST --mesh-config /config/cync_mesh.yaml`.

Leave it on long enough to cover what you care about: a few hours of normal use, plus deliberate events such as
power-cycling the bulb, changing brightness/colour/colour temp from the app and from HA, toggling a switch,
a firmware update.

## Inspect, sanitize, organize
```
uv run python -m cync_lan.capture info /config/captures/*.jsonl
uv run python -m cync_lan.capture organize /config/captures tests/captures
```
`organize` runs every file through the sanitizer again (idempotent, so already-sanitized files are unchanged) and
sorts them into `tests/captures/type_<device type>/fw_<firmware>/`. **Read the output files before committing them.**
Add `--no-sanitize` only for private analysis, `--mesh-config` to also remove the values listed in your config.

## Replay in tests
`tests/replay_harness.py` rebuilds the configured nodes from the capture's `info`, replays every `rx` chunk in order
and returns what the session sent back plus the framer/parser counters. `tests/test_replay.py` runs every
`tests/captures/type_*/fw_*/*.jsonl` and asserts: no packet failed to parse, the framer dropped no bytes, and the
capture ends on a packet boundary. New captures are picked up automatically; to pin behaviour of a specific device
(for example "this 0x83 sets brightness to 40"), write a test that loads that file and asserts on
`result.session.node.entities` or `result.tx`.

Unit tests for the capture format itself (round trip, truncation, size caps, sanitizing) are in `tests/test_replay.py`;
live recording through a real session is in `tests/test_session_lifecycle.py`.
