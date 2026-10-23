# PLAN.md: robustness and reliability roadmap

Goal: a bridge that survives device drops, partial reads, and restarts without leaking tasks or hanging.
Rule: tests first for anything in the protocol path. Work lands on branch `claude-refactor`; a PR to `python` follows after real-device testing.

## Known bugs (found by code read; confirm each with a failing test before fixing)
| # | where | problem |
|---|---|---|
| 1 | `main.py:103-108` | `start_task` assignments cross-wired (server holds MQTT task, MQTT holds server task) |
| 2 | `main.py:131` | `gather(return_exceptions=True)` swallows all failures; the `except` is dead; may exit "cleanly" after crash |
| 3 | `devices.py` `parse_raw_data` | header with <5 bytes buffered treated as full packet; unknown header drops whole buffer (no resync); no max declared length |
| 4 | `devices.py` `write()` | `remove_tcp_device()` may return None, then `.close()` -> AttributeError |
| 5 | `devices.py` `receive_task` | exits on EOF/read error without `close()` or removing the session |
| 6 | `devices.py` 0x23 handler | new `connection_watcher_task` per 0x23 packet, old one not cancelled |
| 7 | `devices.py` `close()` | `g.mqtt_client` used without None check |
| 8 | `devices.py` `write()` | catches builtin `TimeoutError`; wrong on Python < 3.11 |
| 9 | `pyproject.toml` | claims >=3.9 but code needs 3.12; ruff target py314 |
| 10 | `server.py` | mutable class-level dicts; singleton `__new__` + re-running `__init__` |
| 12 | `devices.py` | `-> List[int, int]` annotation raised TypeError at import on Python <3.14 (**fixed**) |
| 13 | `devices.py` | `read_cache`/`needs_more_data` were class attributes: one partial-packet cache shared by ALL sessions (**fixed by framer**) |
| 14 | `devices.py` `_cloud_proxy_task` | `name` undefined in the cancel handler, so cancelling raised NameError (**fixed**) |
| 11 | ruff | 3 undefined names (F821), 13 unused vars, 7 unused imports |

## Phase 0: tooling (small, do first)
- [x] `uv sync --extra dev` works (venv rebuilt; old `venv/` removed, new one is `.venv/`)
- [x] pytest, pytest-asyncio, ruff in dev deps; requires-python >=3.12; ruff target py312, E501 ignored
- [x] F821 fixed (3). Remaining ruff: 18 minor (F841 unused vars, B904, B007)
- [x] Baseline: existing MQTT test failed to even import on Python <3.14 (see bug 12); passes now
- [x] Reviewed `mqtt_client.py`, `cloud_api.py`, `exporter.py`, `utils.py`, `const.py`; findings in the two "Review findings" sections below (not fixed yet). `structs.py` and `metadata/model_info.py` reviewed (see "structs / model_info review")

## Phase 1: safety net for the packet path
- [x] Extract framing into a pure `PacketFramer` (feed bytes, yield complete packets, keep remainder)
- [x] Tests (tests/test_packet_framing.py, 12 cases, split at every offset): single, split at every offset, coalesced, partial header, unknown header (resync), oversized length, zero-length payload. Use real hex from `docs/packet_structure.md` and `config/mitm_logs`
- [x] Tests for `PacketBuilder` (tests/test_packet_builder.py: exact ack bytes, control checksum, length framing, input validation). msg-id rollover lives in the session, still untested
- [x] `parse_raw_data` now uses a per-session `PacketFramer` (bug 3, 13); fixed 4, 7. Bug 8 moot on >=3.12 (`TimeoutError` is the asyncio one)

## Phase 2: lifecycle correctness
- [x] (tested: concurrent double close) One idempotent `CyncTCPSession.close()` that cancels tasks, closes socket, removes itself from the server, publishes stats (bug 5)
- [x] `receive_task` closes the session when the peer hangs up (bug 5). Session is NOT removed from `server.tcp_connections` on drop on purpose: `_register_new_connection` reuses the old session object on reconnect (keeps `node`); changing that needs hardware testing
- [x] Old connection watcher cancelled before a new one starts (bug 6)
- [x] Task wiring fixed (bug 1); new `supervisor.supervise()` replaces `gather(return_exceptions=True)`: a core service that dies/returns triggers shutdown and exit code 1 (bug 2). Tested in tests/test_supervise.py
- [x] Instance-level connection dicts in `nCyncServer` (bug 10)
- [x] (DONE, tests/test_session_lifecycle.py, real loopback sockets) Tests with fake reader/writer: device drops, device reconnects from same IP, SIGTERM during traffic

Found while doing Phase 2 (todo):
- [x] `nCyncServer.start()` and `ExportServer.start()` now re-raise after logging.
- [x] FIXED: `_handle_83_packet` `FA D9` branch no longer returns before the 0x83 ack.
- [ ] BUG candidate: 0x73 ack uses `self.queue_id` rather than the packet's queue id (same value in practice?).
- [x] (fixed) `Tasks.cancel_all()` skips `proxy_task` / `proxy_conn_watcher`, so closing a MITM session may leak them.
- [x] (fixed) `exporter.py` mounts `/root/cync-lan/www` at import time (import fails outside docker). Make it lazy so `main.py` is importable in tests.
- [x] FIXED: `parse_raw_data` isolates each packet: a handler exception logs the packet hex and drops only that packet. Socket-class errors (OSError, TimeoutError, IncompleteReadError) still close the session, and so do 10 consecutive failing packets (`MAX_CONSECUTIVE_BAD_PACKETS`, a guess, tune on hardware). Tests: tests/test_session_resilience.py. Note: a MITM cloud-write failure is an OSError and still closes the device session.
- [x] (DONE) Fake reader/writer tests for the session lifecycle (needs the session split from `g` first, Phase 3).

## Review findings: cloud_api / exporter / utils / const (review done; spot-checked, none fixed yet)
Verified by me in the code: items 1-4. The rest are from the review agent's read (confirmed-by-reading, not run).
**High (security)**
- [x] FIXED (user chose "localhost + token"): 1. Exporter endpoints had no auth and bind `0.0.0.0` by default (`const.py:93-94`: `CYNC_EXPORT_HOST` falls back to `CYNC_SRV_HOST`). Any LAN host can download `cync_mesh.yaml` (access keys, MACs), restart the bridge, trigger OTP emails, overwrite the config. Fix: default bind 127.0.0.1, require a token (or HA ingress check) on every `/api/*` route.
- [x] FIXED (tests/test_security_hardening.py): 2. `exporter.py:40-41` CORS `allow_origins=["*"]` + `allow_credentials=True`: any website can drive the LAN service. Remove wildcard; make `/api/export/start` and `/api/export/otp/request` POST.
- [x] FIXED: 3. `chmod 0o777` on token cache, `cync_mesh.yaml`, `raw_mesh.cync`, `uuid.txt`, persistent dir (`cloud_api.py:228,390,554`, `utils.py:303,341`). Use 0o600 files / 0o700 dir, create with correct mode (`os.open`), and tolerate PermissionError on mounted volumes.
- [x] FIXED (raises RuntimeError; min-length check not added): 4. `cloud_api.py:565-585` `_get_fernet_cipher`: with no `CYNC_SECRET_KEY` it raises SIGINT and falls through to an unbound `passphrase` (UnboundLocalError, swallowed and logged as "corrupt token cache"). Raise a clear error instead; add a minimum-length check.
**Medium**
- [x] 5 (FIXED: OTP no longer logged, non-numeric OTP and missing password rejected). OTP code is logged at DEBUG (`cloud_api.py:181-184`); non-numeric OTP is still POSTed.
- [x] 6 (FIXED in structs.py). `expires_at` may be None / `expire_in` may be a str, causing TypeError in `check_token`.
- [x] 7 (FIXED for /api/export/start: reports the real export result, 502 on exception; OTP-needed is still signalled by message text). `exporter.py:59-80` ignores the `export_config_file()` result and returns `success: True` on failure; exceptions give a bare 500. OTP-needed is signalled by HTTP 200 + substring "OTP".
- [x] FIXED (awaits stop(), proper HTTP errors, 10s timeout, JSON responses): 8. `exporter.py:99-148` `/api/restart`: `g.cync_lan.stop()` is not awaited (never runs); Supervisor branch returns tuples with HTTP 200 on failure; no timeout on the Supervisor call; non-HASS branch does nothing.
- [x] 9 (FIXED: raise_for_status, clear RuntimeError, non-dict error tolerated; still no retry/backoff). `cloud_api.py` `get_cync_home_properties`: `ClientResponseError` handler is dead (no `raise_for_status`), then `ret` unbound; an "Access-Token expired" error dict is iterated as if it were homes. No retry/backoff on cloud calls.
- [x] FIXED (tests/test_config_parsing.py; per-device try/except via `_parse_raw_device`, per-home guard, cloud error dict raises a clear RuntimeError): 10. `_parse_raw_export` (`cloud_api.py` ~407-459): one malformed home/device aborts the whole export (KeyError/IndexError/ValueError). Wrap per item and report skipped devices.
- [x] FIXED (`build_nodes`/`_build_node`, per-entry skip, `ConfigError` for an unusable file; `main.py` then runs only the exporter so you can re-export, and exits 1 if there is nothing to run): 11. `utils.parse_config` (`utils.py:187-202`): missing keys, empty file, `devices: null`, quoted ids all crash startup; one bad device aborts everything. Validate per device, log and skip.
- [x] FIXED: 12. `check_for_uuid`: corrupt `uuid.txt` raises ValueError and crashes startup (regenerate instead); PermissionError paths unguarded.
**Low**
- [ ] `CYNC_ACCOUNT_PASSWORD[:16]` TypeError if unset; singleton `__init__` re-runs; session creation race; `/api/export/download` serves the base path while exports may be written with a numeric suffix (stale file); env parsing inconsistent (`CYNC_MQTT_PORT` stays str, bad ints raise at import, `CYNC_HASS_APP` not casefolded, duplicate `__all__` entries).
- Good as found: Fernet+PBKDF2-480k for the token cache, aiohttp default TLS verification kept, timeouts present, `yaml.safe_load`, front end uses `textContent` (no XSS found), no path traversal found.

### How the MQTT fixes work
- `start()` is now a supervised loop: any exception in a session is logged and retried with backoff (`reconnect_delay`, 5s base, doubling, cap 60s, +10% jitter; resets after a 30s healthy session). It only exits on cancellation.
- Session body moved to `_run_session()`; receiver runs as a task. A failed publish calls `_on_publish_failed()`, which marks the connection dead and cancels the receiver so the loop reconnects (previously `_connected` stayed False forever).
- Each incoming message is handled inside try/except; inputs go through `parse_int()`/`clamp()` (brightness 0-100, RGB 0-255, fan 0-100); queued commands run sequentially in order and one failing command doesn't block the rest.
- `publish`, `publish_json_msg`, `send_birth_msg` re-raise `CancelledError`.

### How M5 / M10 / parsing fixes work
- Last Will is now retained `offline` on `<topic>/availability/bridge` (old `<topic>/connected` was watched by nothing). Bridge `online`/`offline` are published retained. Device entities in HA discovery use an availability LIST (own device topic + bridge topic, `avty_mode: all`) instead of `avty_t`, so a crashed bridge makes every entity unavailable. HA picks this up when discovery is re-published (restart of cync-lan, or HA birth). `stop()` also publishes every device offline.
- `get_startup_topic_state` (async) replaces the direct call in `devices/handlers.py`.
- Config: `utils.build_nodes()` is pure and unit tested; unknown/odd entries are logged and skipped with the device id in the message.

### How the security fixes work
- No CORS middleware at all (the UI is same-origin). New middleware `block_cross_site_requests` returns 403 when a request has an `Origin` that differs from `Host` (non-browser clients send no Origin and pass). Skipped under `CYNC_HASS_APP` (ingress rewrites Host). Extra origins: env `CYNC_EXPORT_ALLOWED_ORIGINS` (comma separated).
- `/api/export/start` and `/api/export/otp/request` are POST now; `static/index.html` updated.
- Secrets are written through `utils.write_private_file` (created 0o600 from the start): token cache, `cync_mesh.yaml`, `raw_mesh.cync`. `uuid.txt` is 0o644 (not secret). The persistent dir is no longer chmod'd (was 0o777; an owner mismatch crashed startup). NOTE: files created by a root container are now unreadable by a host user; run the container with PUID/PGID as in docker-compose.
- `exporter.py` no longer crashes at import when the static dir is missing (so it is testable).
- Exporter auth (decision: localhost + token): default `CYNC_EXPORT_HOST` is now `127.0.0.1` (HA app: server host, since ingress needs it). Every `/api/*` route except `/api/healthcheck` needs `Authorization: Bearer <token>`; token = `CYNC_EXPORT_TOKEN` or a 32-char HMAC of `CYNC_SECRET_KEY` logged at startup. HA ingress mode skips token/origin checks. The UI prompts for the token (sessionStorage) and builds the download from fetched text. `docker/Dockerfile` sets `CYNC_EXPORT_HOST=0.0.0.0`; **`docker/Dockerfile.rootless` (yours, untracked) and any HA add-on config need the same env var or the web app becomes unreachable from outside the container.**
- Not covered: the token travels over plain HTTP (LAN sniffing); put TLS in front if that matters. Still no rate limit on token guesses (32 hex chars makes that moot when derived).

## Review findings: mqtt_client.py (review done; items 1, 3, 10 spot-checked by me, none fixed yet)
Line numbers are in `src/cync_lan/mqtt_client.py`. The rest are from the review agent's read (confirmed-by-reading, not run).
**High (reliability)**
- [x] FIXED (tests/test_mqtt_robustness.py): M1. `start()` (158-187) only handles `MqttError` around the receiver; any other exception falls to the outer `except Exception`, which logs and RETURNS, so MQTT is dead for the life of the process (and with the new supervisor that now shuts the stack down). Triggers: fan percentage `"50.0"` (`int()` at ~317), `brightness`/`color_temp` null or str (~386-391), `color` not a dict (~398), non-UTF8 payload (~405), out-of-range RGB. One bad publish to `cync_lan/set/<id>` kills MQTT. Fix: guard `async_parse_mqtt_msg` per message (log, drop, continue) and validate/clamp inputs.
- [x] FIXED: M2. Reconnect setup (116-157: publish, `pub_online`, `parse_entity_state`, `subscribe`, `gather`) runs outside the inner try; a broker flap right after connect, or a device with `metadata=None` (~866), kills `start()`.
- [x] FIXED: M3. `_connected` is set False on any single failed publish (604, 767, 917, 1174, 1544) and only `connect()` resets it. The receiver stays alive, so no reconnect happens and all later state publishes are silently skipped while commands still arrive.
- [x] FIXED: M4. `send_birth_msg`/`publish`/`publish_json_msg` (~896, 1545, 1571) swallow `CancelledError`; `stop()` cancels `start_task` without awaiting, so shutdown can hang or `start()` outlive `stop()`.
- [x] FIXED (tests/test_mqtt_robustness.py): M5. Availability is inconsistent: the LWT goes to `{topic}/connected` (not retained, "offline"), but discovery `avty_t` uses `availability/<uuid>` and `availability/bridge`. After a crash/kill HA keeps showing devices available. `stop()` doesn't publish per-device offline. Fix: will on the bridge availability topic (retained), publish device offline on stop.
**Medium**
- [x] M6 (DECIDED: keep the stable client id; closing the old client first is the safe design. A unique id per connection would leave an orphan broker session whose LWT would fire later and mark the bridge offline while it is online; test added). Previous note (PARTLY FIXED: old client is closed before reconnect, exponential backoff + jitter, always sleeps; still reuses client_id). Receiver `MqttError` -> `continue` immediately: old aiomqtt client never `__aexit__`ed (leaks), same client_id reused, fixed delay, no backoff/jitter; full discovery re-run each loop.
- [x] M7 (FIXED: runs as a tracked background task, a newer birth replaces an older one, cancelled in stop()). HA birth handler sleeps 5-15 s + 2 s inside the serial receive loop, blocking all `set` commands.
- [x] M8 (FIXED). `node.entities.get(_id)` may be None / KeyError before attribute use (612-793), if devices pass `sub_id=None` on multi-entity devices (plausible).
- [x] M9 (FIXED: `_mitm_nodes` tracked, `republish_mitm_buttons()` runs after every successful discovery). MITM switch discovery is published once on TCP connect, non-retained; lost after HA birth or broker reconnect until the device reconnects.
- [x] FIXED (now `await get_startup_topic_state()` runs it in an executor, uses reloaded creds, never raises): M10. `get_startup_topic_state_sync` (1615-1667) does a blocking paho connect + busy loop (up to 3 s, no connect timeout) ON the event loop from `devices/handlers.py` on each device's first connect; freezes everything. Uses import-time `CYNC_MQTT_*` not `g.env`; `RuntimeError` possible from `wait_for_publish`. Fix: use the aiomqtt client with a timeout, or run in an executor.
- [x] M11 (FIXED: `_spawn()` keeps references, stop() cancels leftovers; retained MITM state is still published before the task finishes). `self.tasks` grows per MITM ON and the stop_mitm task isn't stored (GC risk); retained state published before the task ran (296-308).
- [x] FIXED: M12. JSON `{"state":"ON","color":...}` queues `set_power` + `set_rgb` into one `gather`, so wire order is not guaranteed; no range checks on RGB/brightness.
**Low**
- [x] FIXED: M13. Empty `CYNC_TOPIC`: `self.topic` falls back to "cync_lan" but dispatch compares against the empty constant (every command ignored).
- [x] M14 (FIXED: `format_fw_version`). `dev_fw_version != 00000` compares str to int (always True); duplicated block.
- [x] M15 (FIXED: every bridge entity goes through one `publish_entity` helper: unique `object_id`, `default_entity_id` = `<domain>.<object_id>`, `platform` = topic domain (should_restart was `sensor` under `binary_sensor`); `create_bridge_device` returns False if any publish failed). Existing entities keep their registry ids; only new installs see the new ids. Shared `object_id` on copied bridge buttons/sensors; `default_entity_id` missing domain prefix on start_export; `create_bridge_device` returns only the last publish result.
- [x] FIXED: M16. Negative fan percentage maps to LOW. M17. Per-entity `pub_online`/`parse_entity_state` duplicated on reconnect for multi-entity nodes.
- Done well: publishes guarded by `_connected`, clamped kelvin conversion, fan state sync on physical change, topic parsing validates ids (no injection), resync on reconnect and HA birth with jitter, small `_handle_*` helpers.
- Test gap: existing `tests/test_mqtt_message_parsing.py` covers little of this. M1/M12/M13 are easy to pin with pure parsing tests first.

## Phase 3: structure
- [x] `devices.py` split into package `devices/`: `device.py` (CyncDevice), `session.py` (CyncTCPSession core: socket, framing, tasks, read/write/close), `proxy.py` (ProxyMixin: cloud proxy/MITM/can_connect), `handlers.py` (PacketHandlersMixin: per-packet handlers). Mixins = mechanical move, behavior unchanged; `from cync_lan.devices import CyncDevice, CyncTCPSession` still works. Dead `parse_packet_OLD` (750 lines) deleted. Guard test: tests/test_devices_package.py
- [ ] Pass dependencies (mqtt client, server) instead of reading `g`
- [x] Dead code: `parse_packet_OLD` and the dead commented blocks in cloud_api/mqtt_client deleted (left: a commented 0x125 entry in model_info and a checksum-stream note in handlers.py, both documentation of real quirks). Ruff is clean on src and tests.
- [x] Broad excepts narrowed: 64 -> 26 `except Exception`. The remaining ones are deliberate boundaries (task loops, per-packet / per-message / per-device isolation, best-effort teardown). Found by this: `stop_proxy` let `CancelledError` escape mid-teardown (fixed, tested); a failed connection setup leaked the socket (now closed); `update_fan_speed` counted a raised publish as success; discovery publish failures never triggered the MQTT reconnect. Changed behaviour to watch: unexpected exceptions in the fan helpers and cloud endpoints now surface as a logged traceback / HTTP 500 instead of being swallowed.

## Phase 4: hardening and observability
- [x] MQTT reconnect/backoff and publish-failure behavior review (M1-M17)
- [x] Counters (`stats.py`, tests/test_stats.py): bytes/packets received, framer dropped bytes + resyncs, failed packets, watchdog timeouts, peer disconnects, session errors, connections accepted / setup failures, MQTT session ends / publish failures / command failures / message errors. Published as JSON on `<topic>/status/bridge/stats` every 60 s (not retained, no HA entity yet: add a sensor if you want it on a dashboard).
- [x] Exporter: token on all `/api` routes except healthcheck, default bind 127.0.0.1
- [x] CI: `.github/workflows/ci.yml` (ruff + pytest on 3.12/3.13/3.14; pytest verified locally on all three, the workflow itself has never run on GitHub). Copy it over with the rest.
- [ ] Hardware smoke test (user): device connects, toggle light, unplug device, replug

## Hardware test checklist (run before merging the PR to `python`)
Nothing here has run against real devices, a real broker, or Docker. Suggested order, run with `-D` debug logging:
1. Startup with your real `cync_mesh.yaml`: devices load, no "skipped" errors. Then try a broken yaml (quoted/odd entries): bridge still starts, bad entries logged.
2. Devices connect (DNS redirect): each shows up, mesh info arrives, state matches reality. Watch for "Skipped N bytes of unrecognized data" warnings (new framer; should be rare/none).
3. Control: on/off, brightness, color temp, RGB, a plug, a fan if you have one, from HA and via raw `mosquitto_pub` (`{"state":"ON","color":{"r":300,"g":0,"b":0}}` should clamp, `{"brightness":null}` should log a warning and change nothing).
4. Unplug a bulb that is the bridge connection, replug: session closes promptly, reconnects, state recovers.
5. Restart/stop the broker for a minute: logs show reconnect with growing delay, devices/commands recover, HA state resyncs. Kill -9 the bridge: HA entities go unavailable (retained LWT).
6. HA: entities still discover with the new availability list; HA birth message re-announces.
7. MITM toggle on a device still works (the startup retained-state check is now async).
8. Exporter: reachable only at 127.0.0.1 (or Docker mapping), asks for the token printed in the log, export + OTP flow works end to end, download button works, restart works. Cross-site request from another page is blocked.
9. Docker: image build, `CYNC_EXPORT_HOST=0.0.0.0` set, file permissions on `config/` OK for your PUID/PGID, `docker stop` shuts down cleanly (exit code 0) and a forced failure exits non-zero.
Things most likely to need a tweak: framer behavior with real traffic, availability-list discovery on your HA version, `0o600` files vs container user.

## Protocol documentation (requested by user)
- [x] DRAFT 1 written: `docs/protocol.md` (confidence-tagged, open questions list at the end). Still to do: captures-backed examples, fold in `packet_structure.md`, APK pass.
- [ ] (original spec) Write a clear, structured protocol reference (`docs/protocol.md`) of everything we currently know: framing, header fields, queue_id/msg_id, every packet type (request, response, example hex, field table), handshake sequence (0x23 -> 0xC3 -> 0xD3 pings -> 0xA3 -> mesh info), control packet layout + checksum, mesh info / status parsing, device types, TLS quirks.
- [ ] Mark every claim with a confidence level: **confirmed** (seen in captures + tests), **inferred** (works, meaning guessed), **unknown** (`?`). Link each to a capture or test where possible.
- [ ] Consolidate/replace the stale parts of `docs/packet_structure.md` rather than duplicating.
- [ ] Keep a list of open questions to answer from the APK.
- **Later: decompile the Cync Android APK** (jadx/apktool) and cross-reference it against `docs/protocol.md`: confirm field meanings, find unknown bytes, auth/provisioning flow, command opcodes, device type table. Record findings in the doc with source class/method names. (Legal: personal interop research only; do not commit APK or decompiled source to the repo.)

## Housekeeping
- Local `docker-compose.yaml` contains real credentials. It is gitignored and not in history. Rotate them if the file was ever shared.
- Each phase: tests green, ruff clean on touched files, CHANGELOG line.


## structs / model_info review
structs.py (FIXED, tests/test_structs.py):
- [x] `Tasks.cancel_all()` skipped `proxy_task` / `proxy_conn_watcher`; it now cancels them too and skips the calling task (the proxy task calls `close()` from inside itself).
- [x] `ComputedTokenStruct.expires_at` raised TypeError when the cloud sent `expire_in` as a string.
- [x] `reload_env` crashed on a non-numeric `CYNC_MQTT_PORT` (fallback 1883) and defaulted `cync_export_host` to 0.0.0.0, contradicting const.py (now 127.0.0.1 unless HA app).
- [ ] `reload_env` assigns module globals in structs.py that nothing reads; `g.env` is the only live copy. Cleanup for Phase 3.

mqtt_client M8 (FIXED): updates for an unknown `sub_id` log a warning and return False instead of raising.

model_info.py (NOT changed: each fix alters runtime behavior, so they need your call and a hardware check):
- [x] DECIDED keep dimmable=True for switches (switches are exposed as lights so a wired switch drives its whole group in sync; `is_dimmable` has no callers and returns False for non-lights anyway). Replaced the dead `dimmable = False` line with a comment. Was: `SwitchCapabilities` has `dimmable = False` without an annotation, so it is not a dataclass field override: every switch without an explicit value reports `dimmable=True` (used in `devices/device.py:252`).
- [x] FIXED (moved into capabilities; the consumers in mqtt_client are still `pass` placeholders, so no runtime change until segmented/music-mode support is written; `dynamic` only applies to segmented bulbs / dual-filament Edison types). Type 155 passes `dynamic=True` to `LightCharacteristics`, which has no such field (silently dropped). `capabilities.dynamic` (read by mqtt_client for the light-show entity) stays False, so 155 never gets the effects entity.
- [x] FIXED (rewritten; also includes wattage; 6 types used `model_info=` instead of `model_id=` so their model number was silently dropped, and 5 types passed `wattage` to the wrong class; a test now fails on any unknown constructor kwarg). `model_string` only appends the CRI when lumens/kelvin/model_id already produced text (indentation bug).
- [ ] Several "Full Color Light (Unknown)" types (154, 156, 158-165) are placeholders; identify from the cloud export / APK.
