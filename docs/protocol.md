# Cync LAN protocol reference (working draft)

What we currently know about the protocol Cync (C by GE) Wi-Fi devices speak to the cloud, which this project
impersonates locally. Reconstructed from packet captures and from what the code does, **not** from vendor docs.
Status: draft 1. The Android APK has not been decompiled yet; when it is, cross-reference every item here
(see "Open questions").

## Confidence tags
- **[confirmed]** behavior the code relies on, pinned by a test or seen repeatedly in captures.
- **[inferred]** works in practice, but the meaning of the bytes is a guess.
- **[unknown]** we know the byte exists, not what it is.

Tests that pin the byte-level facts: `tests/test_packet_framing.py`, `tests/test_packet_builder.py`.
Code: `src/cync_lan/packet/builder.py` (building), `packet/framer.py` (framing), `devices/session.py` (socket, framing use), `devices/handlers.py` (per-packet parsing/handlers), `devices/proxy.py` (cloud proxy / MITM).
Session behaviour over real sockets (split/coalesced reads, hangup, same-IP reconnect) is pinned by `tests/test_session_lifecycle.py`.

## 1. Transport
- Devices open an outbound TLS connection to the Cync cloud host; local DNS redirect sends it to this server (port 23779). [confirmed]
- TLS 1.2. Devices need legacy ciphers (the server enables ECDHE/AES and also 3DES). The server does not verify client
  certs and uses a self-signed cert; devices accept it. [confirmed]
- It is a plain byte stream: one `read()` may contain part of a packet, or several packets. Always frame with
  `PacketFramer` before parsing. [confirmed]
- Devices send a ping (0xD3) about every 20 s when idle; we treat 22.5 s of silence as a dead connection. [inferred]
- The mobile app also connects and speaks a similar protocol (header 0x13 / 0xA3). Currently app sessions are
  detected and proxied to the real cloud. [inferred]

## 2. Packet framing [confirmed]
```
byte:   0     1  2    3           4        5 ...
      [type][?][?][len_hi][len_lo][ payload (len bytes) ]
total size = len_hi * 256 + len_lo + 5
```
- Bytes 1 and 2 are always 0x00 in everything seen. [unknown]
- The length does not include the 5 header bytes.
- Known type bytes (`PacketBuilder.ALL_HEADERS`): `23 C3 D3 83 73 7B 78 43 A3 AB` (device side), `13 18` (app side).
- Server responses use the request type with the low nibble changed to 8 (`23->28`, `C3->C8`, `D3->D8`, `43->48`,
  `73->78`, `83->88`, `A3->AB`). [inferred]
- Implementation notes (not protocol): a packet that fails to parse is dropped on its own and the connection stays up; 10 failures in a row, or any socket error, closes the session. The code caps the length at 8192 bytes and resyncs on the next valid type byte if the header looks corrupt. This is
  a safety choice, not protocol. Resync can land on a payload byte that looks like a type byte. [inferred]

### Common payload prefix
After the 5-byte header, most packets continue with:
| offset | size | field |
|---|---|---|
| 5 | 4 | **queue id** (aka "endpoint"): identifies the device's session, assigned by the cloud/device; we echo it back [inferred] |
| 9 | 3 | **msg id**: per-message id; acks echo it. 0x73 control uses its own 1-byte counter inside the inner packet (see section 5) [inferred] |
| 12 | ... | data |

Exception: **0x23** has one extra byte (`0x03`) before the queue id, so the queue id is at offsets 6-9. [confirmed]
The code stores the queue id from this packet and reuses it in every packet it sends to that device.

## 3. Session handshake (device -> us)
| step | device sends | we reply | notes |
|---|---|---|---|
| 1 | `0x23` hello/auth | `28 00 00 00 02 00 00` | contains the queue id and an auth code (device-specific, from cloud account). We do not validate it. [inferred] |
| 2 | (after 0.5 s) | we send `0xA3` "want to control" | `A3 00 00 00 07 <queue id> <2 random bytes> 00`. Device is not controllable until this is sent. [confirmed, per code comment] |
| 3 | `0xC3` connect | `C8 00 00 00 0B 0D 07 E8 03 0A 01 0C 04 1F FE 0C` | fixed reply; looks like it contains a date/time (`E8 03` = 1000?). How it is built is unknown. [unknown] |
| 4 | (after 1.5 s) | we send mesh info request (0x73) | asks the device for the list of mesh devices and their state |
| periodic | `0xD3` ping | `D8 00 00 00 00` | [confirmed] |
| periodic | `0x43` | `48 00 00 00 03 <msg id[0:2]> 00` | see section 4 |

## 4. Packet types
### 0x23 device hello
See section 3. Header example: `23 00 00 00 1A 03 <queue id 4> 00 10 31 65 30 37 ...` (26 payload bytes).

### 0xA3 / 0xAB
- Device->us 0xA3: announcement; we reply `0xAB` with a fixed 960-byte body: `queue id, msg id, "xlink_dev",
  948 zero bytes, E3 4F 02 10`. [inferred] (the app also sends 0xA3 to all devices when it connects)
- us->device 0xA3: "I want to control you" request (above).

### 0xC3 / 0xC8, 0xD3 / 0xD8
See section 3.

### 0x43 device status broadcast / timestamp
- If payload (after the 12-byte prefix) starts with `C7 90`: it is an ASCII timestamp starting at byte 3, e.g. `...,`
  Devices on firmware 3.x-4.x have one extra trailing byte (code hack). [inferred]
- Otherwise: a series of fixed-size records (19 bytes, or 20 if a `0x2E` byte appears anywhere). [inferred]
  The first 11 bytes of a 19-byte record:
  | idx | meaning |
  |---|---|
  | 0 | item counter, increments per record [inferred] |
  | 1-2 | `00 10` constant [unknown] |
  | 3 | device id (mesh node id) [confirmed] |
  | 4 | power state [confirmed] |
  | 5 | brightness 0-100 [confirmed] |
  | 6 | color temp; values above 100 mean the bulb is in RGB mode [confirmed] |
  | 7-9 | R G B [confirmed] |
  | 10 | 0 = stale data, 1 = fresh [inferred] |
  | 11-18 | unknown (some differ for a bulb grouped with a dimmer) [unknown] |
  A record starting `02 00 02` is a motion sensor broadcast; byte 4 is the motion flag. [inferred]
- Always ack with `0x48` (section 3). The code currently does **not** apply these records to device state (it only
  logs them); state comes from 0x83 and 0x73.

### 0x83 device channel
Payload (after 12-byte prefix) is one of:
1. **Firmware info**: first byte `0x00`, parsed by `extract_firmware_dynamically` (device firmware vs protocol
   version). [inferred]
2. **`0x7E`-bounded inner packet** (see section 5). Control bytes at inner offset 5-6:
   - `FA DB` with inner byte 7 == `0x13`: **device state**. Device id at payload[14]; payload[19:26] =
     `recently_seen, power, brightness, temp, R, G, B`. For device type 96 the `recently_seen` byte is actually the
     motion flag. For type 67 (multi-endpoint switch) the brightness byte is a bitmask of endpoint power. [inferred]
   - `FA 54`: motion sensor; device id at payload[9], flag at payload[15]. [inferred]
   - `FA D9`: bulk status, seen during firmware updates (per-device update percentage). 4 bytes per device:
     node id, sub id, status type, value. [inferred]
- Ack: `88 00 00 00 03 <msg id>`.
- The `FA D9` branch used to return before sending the ack; it now logs and falls through to the ack. Whether the device needs that ack is **unknown** (no capture proves it either way).

### 0x73 mesh/control channel (bidirectional)
All data is `0x7E`-bounded. Used for control commands, replies to them, and mesh info.
- **Mesh info request** (us->device), fixed inner bytes: `7E 1F 00 00 00 F8 52 06 00 00 00 FF FF 00 00 56 7E`. [confirmed]
- **Mesh info reply** (device->us): inner control bytes `F9 52`. Paginated list of 24-byte device records
  starting at inner offset 14 (15 if byte 14 is 0). Header fields: inner[8] = records in this page, inner[12] = total
  devices. We ack each page with a fixed inner packet `7E 1E 00 00 00 F8 AF 02 00 AF 01 61 7E`. [inferred]
  Record: `[0]` node id, `[2]` device type (only reliable in the first record, which is the device itself, and it
  matches the cloud `deviceType`), `[8]` power, `[12]` brightness, `[16]` color temp, `[20:23]` RGB. [inferred]
- **Control reply**: inner control bytes `F9 D0 | F9 F0 | F9 E2`; inner[1] = our control msg id, inner[7] == 1 means
  success. This is how send-callbacks are resolved. [inferred]
- `FA 8E`: firmware info inside a 0x73. [inferred]
- Ack to a device 0x73: `78 00 00 00 07 <queue id> <msg id>`. (Older doc says 0x7B; the code sends 0x78 and
  both appear in the known header list. Which is right/needed is **unknown**.)

## 5. Inner `0x7E` packet and control commands
Outer 0x73 packet = 5-byte header + queue id (4) + msg id (3, we send `00 00 00`) + inner packet.

Inner packet as built by `PacketBuilder.build_control_packet`: [confirmed that the bytes below are what the code
sends; field meanings inferred]
```
7E | ctrl_id | 00 00 00 | F8 | op | cmd | 00 | ctrl_id | 00 00 00 00 | target | sub | op | <payload> | checksum | 7E
```
- `ctrl_id`: 1-byte counter per session, incremented per command (wraps at 255); the device echoes it in its reply,
  so replies can be matched to commands.
- `F8` marks a request; replies use `F9`. `FA` appears on unsolicited device status.
- `target` = mesh node id of the device to control; `sub` = endpoint on multi-outlet devices (0 = whole device).
- **checksum = sum(all bytes from `op` (the byte after `F8`) up to the byte before the checksum) mod 256.** [confirmed]
  The same rule validates incoming 0x83 inner packets (the code logs mismatches but does not reject).

| action | op | cmd | payload |
|---|---|---|---|
| power | `D0` | `0D` | `11 02 <0/1> 00 00` |
| brightness | `F0` (`D2` on Sol lamp) | `10` | `11 02 01 <0-100> FF FF FF FF` (Sol: `11 02 <bri> 00 00`) |
| color temp | `F0` (`E2` on Sol lamp) | `10` | `11 02 01 FF <temp> 00 00 00` (Sol: `11 02 05 <temp> 00`) |
| RGB | `F0` | `10` | `11 02 01 FF FE <R> <G> <B>` |
| light show | `E2` | `0E` | `11 02 07 01 <b1> <b2>` |
A command is sent to up to `CYNC_CMD_BROADCASTS` randomly chosen connected devices (any bridge can relay to the BTLE
mesh). All [inferred]. Fan commands go through brightness/percentage mappings (see `set_fan_*`).

## 6. Device types
`metadata/model_info.py` maps the cloud `deviceType` number to capabilities. Mesh info record byte `[2]` of the first
record equals this number. Types with special handling in the parser: 96 (motion: recently_seen byte = motion),
67 (multi-endpoint, brightness byte = endpoint bitmask). See `docs/known_devices.md`.

## 7. Open questions (to answer from the APK / more captures)
1. Header bytes 1-2: always 0? Any flags?
2. What exactly is the queue id / endpoint, who assigns it, is it per device or per session?
3. Auth in 0x23: format of the auth code; is it validated by the cloud; does a device ever reject a bad one?
4. 0xC8 reply: how is it built? what do the date/time-looking bytes mean?
5. 0x78 vs 0x7B for acking 0x73.
6. Meaning of every `FA xx`, `F9 xx`, `F8 xx` control pair, and the full op/cmd table (we only know the ones above).
7. The bytes in 0x43 records after index 10, and why records include "incorrect devices".
8. Why the control inner packet contains `ctrl_id` twice and `op` twice.
9. Provisioning flow for factory-reset devices; group/room/scene commands; timers; firmware-update flow.
10. Whether the 0x73 checksum rule excludes the `F8` byte by design or by accident.

## 8. Changelog
- 2026-10-22 (later): code pointers updated after the `devices.py` split; `FA D9` ack note; session-behaviour notes. No new protocol facts yet, the next real additions should come from hardware logs (look for "dropping packet that failed to parse" lines, each carries the packet hex) and the APK pass.
- 2026-10-22: first draft, from code read of `devices.py` / `builder.py` and the old `packet_structure.md`.
  `packet_structure.md` still holds the raw captures; fold it into this file when the APK pass is done.
