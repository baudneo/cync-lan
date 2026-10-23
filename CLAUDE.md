# CLAUDE.md

## What this is
`cync-lan`: a local async bridge between Cync (C by GE) Wi-Fi devices and MQTT / Home Assistant.
Devices are DNS-redirected to this server, which terminates their TLS connection (port 23779),
speaks the Cync binary protocol, and republishes state/commands over MQTT. An optional FastAPI
"exporter" (port 23778) pulls the device list from the Cync cloud account. Optional MITM mode
proxies a session to the real Cync cloud.

## Workflow and safety
- This code was largely refactored with Claude (branch `claude-refactor`); see `PLAN.md` for what changed and why,
  and the hardware test checklist. Do not commit unless asked, and never push to `python`/`main` directly.
- Never read, print, or commit: `certs/`, `config/` (uuid.txt, mitm_logs, mesh yaml), the root `docker-compose.yaml`
  (holds real credentials), `.env` files, or the Cync APK / decompiled code.

## Layout (`src/cync_lan/`)
| file | role |
|---|---|
| `main.py` | entrypoint, `CyncLAN` starts server + MQTT + exporter tasks, signal handling |
| `server.py` | `nCyncServer`: TLS listener, owns `tcp_connections` (ip -> `CyncTCPSession`) |
| `devices/device.py` | `CyncDevice`: entity model, command senders (set_power, set_brightness, ...) |
| `devices/session.py` | `CyncTCPSession`: socket read/write/close, framing, packet dispatch, background tasks |
| `devices/handlers.py` | `PacketHandlersMixin`: per-packet-type handlers (0x23/43/73/83/A3), mesh info |
| `devices/proxy.py` | `ProxyMixin`: cloud proxy / MITM logging / connection gating |
| `packet/framer.py` | `PacketFramer`: pure byte-stream -> complete packets |
| `stats.py` | `stats`: process-wide event counters, published to `<topic>/status/bridge/stats` |
| `capture.py` | record raw device traffic (`CYNC_CAPTURE_DIR`), load/sanitize/organize captures; replay harness is `tests/replay_harness.py` (docs/capture.md) |
| `supervisor.py` | `supervise()`: service-task supervision used by `main.py` |
| `packet/builder.py` | `PacketBuilder`: header constants, ack/control/mesh-info packet builders |
| `mqtt_client.py` | MQTT + Home Assistant discovery, command parsing |
| `structs.py` | `GlobalObject` (`g`, shared singletons), dataclasses |
| `const.py`, `utils.py` | env-driven config, helpers, config parsing |
| `exporter.py`, `cloud_api.py` | cloud export web app |
| `metadata/model_info.py` | device type -> capabilities table |

## Protocol cheat-sheet (verify against `docs/packet_structure.md`)
- Packet = 5-byte header + payload. Header: `[0]` type, `[3]` length multiplier, `[4]` length.
  Total bytes = `byte3*256 + byte4 + 5`. TCP is a stream: reads may split or coalesce packets.
- `parse_packet` reads queue_id = `data[5:9]`, msg_id = `data[9:12]`.
- Device-to-server types: 0x23 auth/hello, 0xC3 connect, 0xD3 ping, 0x43/0x83 status, 0x73 mesh/control, 0xA3 app hello.
  Server acks use the type with low nibble 8 (0x28, 0xC8, 0xD8, ...).
- Control packets: checksum = `sum(inner[5:]) % 256`, framed by 0x7E boundary bytes.
- TLS: server must accept legacy ciphers and `CERT_NONE` because devices require it. Keep LAN-only.

## Commands
```
uv sync --extra dev            # creates .venv/
uv run pytest -q
uv run ruff check src tests    # kept clean; CI (.github/workflows/ci.yml) runs both on 3.12-3.14
uv run python -m cync_lan.main --debug --env path/to/.env
```
Requires Python >= 3.12 in practice (3.12-only f-string syntax is used).

## Conventions
- Match existing style: log prefix `lp = f"{self.lp}name:"`, f-string logging.
- Do not add new globals on `g`; pass dependencies in.
- No new bare/broad `except Exception` that just logs and continues. Catch specific errors; always re-raise `CancelledError`.
- Every protocol/framing fix gets a test that fails first. Prefer pure functions (bytes in, bytes out).
- Keep tasks referenced (store the `Task`), cancel and await them on close.
- Don't "fix" the TLS settings or packet quirks without a captured packet proving the change.

## Protocol docs
The user wants a clear written reference of what is known about the protocol (`docs/protocol.md`, see PLAN.md). Keep it
updated whenever you learn or confirm something, tagging claims confirmed / inferred / unknown. The Cync APK will be
decompiled later to cross-reference it; do not commit the APK or decompiled code.

## Status
Roadmap and known bugs are in `PLAN.md`. Read it before starting work.
