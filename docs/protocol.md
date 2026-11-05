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
| 5 | 4 | **queue id** (aka "endpoint"): identifies the device; in the 0x23 hello it is the device's cloud `switchID` (big-endian), see section 7 [confirmed for 0x23]; we echo it back |
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
| periodic | (every `CYNC_MESH_REFRESH_SECS`, default 90 s) | we resend the mesh info request (0x73) | a bridge seems to push 0x83 stale flags (a bulb that lost power) only for a few minutes after a mesh info request; without re-asking, a bulb cut later is never reported. A/B on real hardware: refresh off 0/8 bulbs went offline, 90 s 8/8 (baudneo/cync-lan#39). [inferred] |
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
  | 6 | mode: 0-100 = white, color temp [confirmed]; `FE` = RGB [confirmed]; `80`+index-1 = light show index running, `E3` = Cyber (index `43`); `A0`+index-1 = music show index running [confirmed on type 75, see run modes in section 5] |
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
   - `F9 52`: a **mesh info reply**, the same records as the 0x73 one, sent on 0x83 by some bridges (on one 3-home
     account every bridge of the two biggest homes, 35 and 51 devices). **Byte-stuffed** [confirmed 2026-11-04]:
     `7D xx` stands for `xx ^ 0x20` (`7D 5E` = `7E`, `7D 5D` = `7D`). After un-stuffing, the checksum (last byte before
     the closing `7E`, = sum of inner bytes from index 5) matches and the page holds exactly inner[12] 24-byte records
     from inner[14], the bridge's own record first; without un-stuffing the checksum fails. One page held the whole
     home (35 and 37 records). inner[8] is NOT the record count here (47 on a page of 37). Parsed since 2026-11-04
     (`_process_83_mesh_info`); before that it was logged as UNKNOWN, so after a restart such a home's devices stayed
     offline. Acked as a normal 0x83 (no extra 0x73 mesh ack). Why some bridges use 0x83: unknown.
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
- `target` and `sub` together look like one **16-bit little-endian mesh destination** (`target` = low byte, `sub` = high
  byte) [inferred]. Devices are below `0x8000`; a **group (Cync room)** is its cloud `groupID` (`0x8000-0xFFFF`,
  `groupsArray` in the home properties), sent in the same two bytes. The cloud integration cync_lights sends its room
  commands exactly this way (`groupID.to_bytes(2, "little")` in this field, through the cloud's TCP server), and the
  decompiled app's `MeshAddress` puts group addresses at 32768-65535 (Proxy-alt/cync-lan `docs/mesh_opcodes.md`). Seen
  2026-11-04: a room toggled from the app made all 4 members report their new power in ONE 0x83 burst, while 9
  per-device commands from HA spread over 100 ms - 1 s. Sending to the group address from cync-lan: **not yet confirmed
  on hardware** (`devices/group.py`, test in progress).
- **checksum = sum(all bytes from `op` (the byte after `F8`) up to the byte before the checksum) mod 256.** [confirmed]
  The same rule validates incoming 0x83 inner packets (the code logs mismatches but does not reject).

| action | op | cmd | payload |
|---|---|---|---|
| power | `D0` | `0D` | `11 02 <0/1> 00 00` |
| brightness | `F0` (`D2` on Sol lamp) | `10` | `11 02 01 <0-100> FF FF FF FF` (Sol: `11 02 <bri> 00 00`) |
| color temp | `F0` (`E2` on Sol lamp) | `10` | `11 02 01 FF <temp> 00 00 00` (Sol: `11 02 05 <temp> 00`) |
| RGB | `F0` | `10` | `11 02 01 FF FE <R> <G> <B>` |
| run mode (light / music show) | `E2` | `0E` | `11 02 07 <mode> <index> <any>` (see run modes below) |
A command is sent to up to `CYNC_CMD_BROADCASTS` randomly chosen connected devices (any bridge can relay to the BTLE
mesh). All [inferred]. Fan commands go through brightness/percentage mappings (see `set_fan_*`).

### Group membership (op `8E`, inner op `D7`) [confirmed 2026-11-04 from the app's own packets]
Captured with the app relayed to the cloud through cync-lan (app proxy + a hybrid bridge), creating / deleting a group
and a room for one switch. Sent to the device's own address:
```
7E <ctrl> 00 00 00 F8 8E <len> 00 <ctrl> 00 00 00 00 <dev lo> <dev hi> D7 11 02 <01 join | 00 leave> <grp lo> <grp hi> [flag] <ck> 7E
```
- `<len>` = 8 + the number of bytes after `D7` (also true of `D0` power: 13, `F0` brightness: 16). Same checksum rule.
- The byte after the destination is `D7`, not the outer op again (`PacketBuilder.build_control_packet(inner_op=0xD7)`).
- `flag` (joins only): `00` for a plain group or room; `87` when the device re-joins its ROOM because it now also has a
  group inside that room. Removing the group, the room is joined again with `00`.
- To move a switch between rooms the app sends leave (old room) + join (new room).
- The device answers `F9 8E 01` (ok) and then reports its group list:
  `7E <ctrl> 00 00 00 FA 8E 20 00 <3 bytes> <dev> 00 00 00 D4 11 02 <8 slots> ...` where a slot is the LOW byte of a group
  id (`FF` = empty): a device is in at most 8 groups, all `0x80xx`.
- The app allocates new ids upwards from the highest one in the account (a new group got `0x801A` after `0x8019`).
- A room or group with one member is switched by the app with a command to that device, not to the group address.
- Other `8E` sub-commands seen: `EA 11 02 10 09` (device info query, reply `EA 11 02 <dev> 89 ...`), `F7 11 02 03 01|02`
  (while editing, reply `EA ... 81 50 ...`); `F8 AF 02 00 AF 01` to the bridge every 60 s from the app. Meanings unknown.

### Run modes (light shows, music shows) [confirmed on type 75, fw 1.0.516; other types untested]
Measured one command at a time (2026-10-25): each command sent, the device's status read back (0x43 record byte 6), and the
Cync app's highlighted tile and the light itself checked by eye. Code: `cync_lan/effects.py`.
- `<mode>`: `00` exit the running show, `01` light show, `02` music show. Mode values first published by homebridge-cync-app
  (`src/cync/tcp-client.ts`, `buildRunModePacket`).
- `<any>`: the last byte did not matter for any show tested (homebridge sends a random nonce there). [confirmed]
- Light show index (app tile name): 1 Candle, 2 Rainbow, 3 Fireworks, 4 Volcanic, 5 Aurora, 6 Happy Holidays,
  7 Red White Blue, 8 Vegas, 9 Party Time, `43` Cyber. The app shows Cyber third, so tile order is not index order.
  `64` did nothing. Fireworks is per deviceType: `3A` on the devices `FACTORY_EFFECTS_BYTES` was built from, but on
  type 75 `3A` did nothing (also with last byte `DA`) and `03` runs it (`LIGHT_SHOW_ID_OVERRIDES`).
- Music show index: 1 Midnight, 2 Earth Tones, 3 Heat Wave, 4 Solar Flare, 5 Breeze, 6 Tropical, 7 Spectrum, 8 Supernova.
  Index 9 never answered.
- Custom shows (the app's Custom tab) start at index 10 in both modes. With every slot the app allows filled, light shows ran
  at 10-32 and music shows at 10-19; 33 / 20 did nothing. Custom tile order in the app is not slot order. The command carries
  only the slot number: the show itself is stored when the user saves it in the app. Deleting a custom show did not renumber
  the later ones. A newly saved show took a freed slot. [confirmed]
- Status byte 6 reports the running show: `80`+index-1 for light shows (`E3` for Cyber), `A0`+index-1 for music shows, for
  presets and custom slots alike. A deleted slot still answered with its code once, then the device went back to the
  previous show about 5 s later (seen once). [inferred for the deleted-slot case]
- The light-show code range `80`-`9F` ends where music codes begin, which is probably why custom light slots stop at 32. [inferred]

## 6. Device types
`metadata/model_info.py` maps the cloud `deviceType` number to capabilities. Mesh info record byte `[2]` of the first
record equals this number. Types with special handling in the parser: 96 (motion: recently_seen byte = motion),
67 (multi-endpoint, brightness byte = endpoint bitmask). See `docs/known_devices.md`.

## 7. Homes (multiple meshes per account)
User guide: `docs/multi_home.md`. Code: `devices/registry.py` (`DeviceRegistry`, `HomeResolver`).
- A Cync account can hold several homes. Each home is a separate BLE mesh with its own `access_key` (cloud export,
  per home). [inferred from the export layout]
- Mesh node ids are assigned per home and restart at 1 in every home, so the same id exists in several homes.
  [confirmed: seen in a 4-home account export, ids 1..N in every home]
- The exporter takes the first 9 digits of the cloud `deviceID` as the home id and the last 3 as the node id. [inferred]
- A device added in the app after the last export gets an id its home does not have in the config (most likely the
  next free id of that home). With nested ids that id usually exists in a bigger home, so one reported id is no proof
  of a bridge's home; the fingerprint (`docs/multi_home.md`, signal d) weighs ids a home lacks against ids it has that
  were not reported. [inferred: next-free-id assignment not confirmed]
- A bridge (device with a TCP session) reports and relays only its own home's mesh: the mesh-info pages and 0x83 status
  it sends carry bare node ids with no home field. [inferred]
- Control packets carry no home field either: `target` is the bare node id, so a command sent through a bridge of the
  wrong home would most likely reach the device with the same id in that bridge's home. [inferred, not tested]
- No packet carries a home field, but the 0x23 **queue id** (4 bytes at offsets 6-9) identifies the device: read
  big-endian, it equals that device's cloud `switchID` (`bulbsArray[].switchID`, exported as `switch_id`), and the
  export tells which home that device is in. [confirmed 2026-11-04 in a 4-home account: 5 type 53 switches (fw 1.0.110) and 4 type 137
  bulbs (fw 1.0.380); each sent its own switchID, the same value on every reconnect; all 4 homes resolved by it] It is not the home id.
  Only Wi-Fi devices have a switchID in the export (103 of 105 devices; the 2 without are BT-only), which fits: only
  Wi-Fi devices open a TCP session. Other device types and firmware versions are untested. The code logs every queue
  id at INFO with what it matched and uses a match to pick the bridge's home.
- The mesh-info header byte inner[12] ("total devices") is not used to identify the home: it may differ from the
  configured count (offline devices, paging). [inferred]
- How cync-lan picks a bridge's home, in order: only one home configured; the IP is in the home's `bridges:` list
  (user config); queue id match; fingerprint of the reported node ids (an id not reported is never evidence). This is
  implementation, not protocol.

## 7b. What the cloud needs to show a device online [confirmed 2026-11-04]
The Cync app shows a Wi-Fi device as online only while that device has its own TCP connection to the cloud: a bridge
relaying every mesh device's 0x83 status was not enough. A connection relayed by cync-lan (MITM / hybrid relay) counts,
and cync-lan can keep writing its own 0x73 commands into it (docs/hybrid_relay.md). The app itself must reach the cloud
too (its own TCP connection, port 23779, same DNS name as the devices).

## 8. Open questions (to answer from the APK / more captures)
1. Header bytes 1-2: always 0? Any flags?
2. ~~What exactly is the queue id?~~ Answered for the 0x23 hello (section 7): it is the device's cloud `switchID`,
   per device and stable across reconnects [confirmed on type 53 fw 1.0.110 and type 137 fw 1.0.380]. Still open: is it the same on every
   device type and firmware (users: report the `0x23 queue id ...` INFO line, see `docs/multi_home.md`); do the
   queue ids in other packet types (0x43 example `16 b0 56 fc`) always equal the session's 0x23 value; where the APK
   assigns it.
3. Auth in 0x23: format of the auth code; is it validated by the cloud; does a device ever reject a bad one?
4. 0xC8 reply: how is it built? what do the date/time-looking bytes mean?
5. 0x78 vs 0x7B for acking 0x73.
6. Meaning of every `FA xx`, `F9 xx`, `F8 xx` control pair, and the full op/cmd table (we only know the ones above).
7. The bytes in 0x43 records after index 10, and why records include "incorrect devices".
8. Why the control inner packet contains `ctrl_id` twice and `op` twice.
9. Provisioning flow for factory-reset devices; scene commands; timers; firmware-update flow. Group control: see section 5
   (addressing inferred, hardware test pending).
10. Whether the 0x73 checksum rule excludes the `F8` byte by design or by accident.

## 9. Changelog
- 2026-11-04 (groups): group membership command (8E / D7), the group-list report and the room flag, from app captures.
- 2026-11-04 (0x83 mesh info): `F9 52` on 0x83 confirmed byte-stuffed and parsed (section 4, 0x83).
- 2026-11-04 (group commands): section 5, the control destination is 16-bit (`target` low, `sub` high) and a Cync room
  is addressed with its cloud `groupID` (inferred from cync_lights and the app; hardware test pending).
- 2026-11-04 (later): `F9 52` mesh info replies seen on 0x83 (section 4, 0x83), with probable `7D 5E` byte stuffing.
- 2026-11-04: confirmed on hardware that the 0x23 queue id is the device's cloud `switchID` (type 53 switches fw
  1.0.110, type 137 bulbs fw 1.0.380, stable over reconnects), not the home id. Section 7 and open question 2 updated.
- 2026-11-03: multi-home. New section 7 (homes: one BLE mesh and `access_key` per home, node ids restart at 1, no home
  field in mesh-info / status / control packets). Devices are keyed by (home id, mesh id) and each bridge session is
  matched to its home; the 0x23 queue id is logged at INFO to test the hypothesis in open question 2. No new confirmed
  packet facts.
- 2026-10-26: run modes (light / music shows, custom slots, exit) and status byte 6 as the running-show code, measured on a
  type 75 (nathandlawrence-bot). Fireworks is index 3 on type 75 (`3A` elsewhere).
- 2026-10-22 (later): code pointers updated after the `devices.py` split; `FA D9` ack note; session-behaviour notes. No new protocol facts yet, the next real additions should come from hardware logs (look for "dropping packet that failed to parse" lines, each carries the packet hex) and the APK pass.
- 2026-10-22: first draft, from code read of `devices.py` / `builder.py` and the old `packet_structure.md`.
  `packet_structure.md` still holds the raw captures; fold it into this file when the APK pass is done.
