# Multiple Cync homes

A Cync account can hold several homes (for example a house and a cabin). cync-lan supports this. This page explains
how it works, what you may need to add to `cync_mesh.yaml`, and what the log lines mean.

Single-home users do not need to change anything. See [Single-home installs](#single-home-installs) for the small
differences you may notice in the log.

## The problem
Every Cync home is its own Bluetooth mesh, with its own `access_key`. Device ids are given out per home, and they
restart at 1 in every home. So "device 3" exists once in each home.

Before this change cync-lan keyed devices by that bare id. With more than one home, the homes overwrote each other
when the config was loaded: for each id only the last home's device was kept. Devices from the other homes never
showed up in Home Assistant, and state reports or commands could go to the wrong device.

## How devices are keyed now
- Every device is keyed by `(home id, device id)`. The home id is the `id:` of the home in `cync_mesh.yaml`.
- The device id is still the mesh id inside its home. It is what control packets target, so the bytes sent to a
  device are unchanged.
- Home Assistant unique ids, entity ids and MQTT topics already contained the home id
  (`<home_id>_<device_id>`, `cync_lan/set/<home_id>-<device_id>`). **They have not changed.** Existing entities keep
  working. Devices that were hidden by the old overwrite appear as new entities.
- Each home gets its own pool of bridges. A command for a device is sent only through bridges of that device's
  home. The offline vote for a device only counts bridges of its home.

## Bridges and homes
A "bridge" is a Wi-Fi Cync device that holds a TCP connection to cync-lan. It relays commands and status between
cync-lan and the Bluetooth mesh **of its own home only**.

So cync-lan must know which home each bridge belongs to. No packet carries a home field, but the first packet a
device sends identifies the device itself (its cloud `switchID`, see signal c), and the exported config says which
home that device is in. cync-lan works the home out per connection from the signals below. They are listed in the
order they are tried. The first one that gives an answer wins, and later signals never change it.

**Recommended setup with more than one home: re-export your config once with this version** (so every Wi-Fi device
has a `switch_id:`). Then every bridge's home is known from its first packet and you do not need `bridges:`.

| # | signal | when | confidence |
|---|---|---|---|
| a | only one home is configured | at connect | reliable |
| b | the bridge's IP is in that home's `bridges:` list | at connect | reliable (if your list is right) |
| c | the 0x23 queue id equals a device's `switch_id` | first packet | **confirmed** (type 53 and 137); needs a config exported by this version |
| d | the device ids the bridge reports fit one home much better than any other | mesh info / status | **inferred**, weak when ids overlap |

### a) Only one home
If the config has exactly one home with devices, every bridge belongs to it. This is decided when the bridge
connects and it is the same behaviour as before. Empty homes, and homes whose devices are all `enabled: no`, are not
counted.

### b) The `bridges:` list (manual override)
You can list the IPs of a home's bridges in `cync_mesh.yaml`. A bridge whose IP is in exactly one home's list
belongs to that home. This is decided when the bridge connects and it is kept across reconnects.

Use it for a device whose queue id matches nothing (signal c), or to force a home by hand. See
[Adding `bridges:` to cync_mesh.yaml](#adding-bridges-to-cync_meshyaml).

### c) The 0x23 queue id = the device's `switch_id` (confirmed)
The first packet a device sends (0x23) carries a 4-byte "queue id". Read as a big-endian number, it is that
device's cloud `switchID`, which the export writes as `switch_id:`. Each Wi-Fi device has its own, and it stays the
same when the device reconnects. Confirmed in a 4-home account on type 53 switches (firmware 1.0.110) and type 137
bulbs (firmware 1.0.380), with bridges of all 4 homes connected; other device types and firmware versions have not
been checked yet (see [Please report](#please-report-other-device-types)).

If the number equals the `switch_id:` of a device in exactly one home, that home is picked, from the very first
packet, and cync-lan also knows which device the bridge is (its MITM switch in Home Assistant, and commands for that
device go straight through its own connection). With several homes the result is logged at INFO.

`switch_id` is written by the cloud export (see [Re-exporting](#re-exporting-the-config)). **Configs exported
before this change do not have it**, so the queue id matches nothing and cync-lan falls back to signal d, which
often cannot decide. Re-export once. Bluetooth-only devices have no `switch_id`; they never connect over TCP, so
they do not need one.

The queue id is also compared with each home's `id:`. That was the other early guess; it has not been seen to match,
and is kept only in case some firmware does it.

### d) Fingerprint of the reported ids (weak, inferred)
A bridge lists the devices of its own mesh in the mesh info pages it sends after connecting (and every
`CYNC_MESH_REFRESH_SECS`). cync-lan collects every id a bridge lists on this connection and compares the set with
each home in `cync_mesh.yaml`. Ids in status packets (0x83) are not used: a status can carry a group or room id, and
evidence is never removed, so one such id could stop the real home from ever fitting. For each home it counts two
numbers:
- **lacks**: reported ids that this home does not have in the config. If the first mesh info record (the bridge
  itself) carries a device type, and this home's device with that id has a known, different `type:`, that counts as
  one more. A home with no `type:` for that device, or a type byte that matches no home, is not counted against.
- **unreported**: ids this home has in the config that the bridge has not reported (yet).

A home **fits** when it lacks nothing. A home that fits rules out another home only if that other home lacks
**more** reported ids than the fitting home has unreported ids. A home is picked when exactly one home is left and
it fits. Ids that no home has are ignored. The numbers are counted again from everything seen each time a page or
status arrives, so a home is never dropped for good.

**Why not "an id only one home has decides it"?** The config can be older than the account. Ids are given out
per home from 1 up, so a device you add in the Cync app after the last export gets the next free id of its home. If
a bigger home already has that id, the bridge would look like it belongs to the bigger home. Example with fake
homes and nested ids (ids 1..N in every home):

| home | device ids in the config |
|---|---|
| Office | 1-6 |
| Garage | 1-12 |
| Cabin | 1-36 |
| House | 1-51 |

- You add a 37th device to Cabin and do not re-export. A Cabin bridge reports 1-37. House has all 37 ids, but it also
  has 14 ids (38-51) that were not reported. Cabin lacks only one id (37). 1 is not more than 14, so Cabin is not ruled
  out and nothing is picked. You get the "Could not work out" WARNING naming Cabin and House.
- A House bridge reports all 51 ids. Cabin lacks 15 (37-51), Garage 39, Office 45. House has nothing unreported, so
  House is picked. With a few House devices offline it still works: with 3 offline (say 40, 45, 50), House has 3
  unreported and Cabin lacks 12, so House is still picked.
- A Cabin bridge with an up-to-date config reports 1-36. House fits too (it has 1-36), so nothing is picked. That is
  the nested-ids limit: a bridge in a smaller home can never be told apart from a bigger home by ids alone.

Rules:
- **A missing id never picks a home.** Devices can be offline or out of range. Missing ids can only stop a pick
  (the "unreported" number above).
- **One id is never proof on its own.** An id that only one home has just counts against the other homes; it
  decides nothing until that home's other ids have reported too.
- The mesh info "total devices" count is only logged. It is not used to pick a home.

**Why it is weak.** In practice only bridges in the biggest home can be picked this way, and only once most of its
devices have reported. A stale config can still fool it when the change is big: Cabin above is only ruled out once it
lacks more reported ids than House has unreported, so with 8 or more devices added to Cabin since the export (ids
37-44, leaving at most 7 of House's 38-51 unreported) a Cabin bridge would be put in House. A pick by fingerprint is therefore
logged at **WARNING** with the evidence (which ids each other home lacks), so you can check it. Re-export after
adding devices, and use `bridges:` to make the home certain.

### While a bridge's home is not known
- It is connected (see [Connection limit](#connection-limit) for how it was admitted), but it is in no home's pool,
  so **it never gets a command**.
- Mesh info records it sends are held back (at most 256) and applied once the home is known.
- Status packets are dropped (logged at DEBUG) and their ids are not used for signal d. The periodic mesh refresh
  sends that state again later.
- After a full mesh info sequence with no answer, one WARNING per connection tells you which homes are still possible
  and how to fix it (see [Log lines](#log-lines)).
- On every reconnect, signals c and d are learned again from scratch. Signals a and b are re-applied at once.

## Adding `bridges:` to cync_mesh.yaml
Add a `bridges:` list to a home, at the same level as `id:` and `devices:`. Each entry is the IP address of one Wi-Fi
device of that home that connects to cync-lan.

Example (fake values):

```yaml
exported_homes:
  House:
    id: 123456789
    access_key: 111111
    mac: AABBCCDDEEFF0011
    # Wi-Fi devices of this home that connect to cync-lan
    bridges: ["192.168.1.50", "192.168.1.51"]
    devices:
      1:
        name: Kitchen Light
        mac: AA:BB:CC:00:00:01
        wifi_mac: AA:BB:CC:00:01:01
        fw: 1.3.160
        type: 53
        # written by the cloud export when the cloud has one (optional)
        switch_id: 987654321
        endpoints:
          0: Kitchen Light
  Cabin:
    id: 234567890
    access_key: 222222
    mac: AABBCCDDEEFF0022
    bridges:
      - 192.168.1.60
    devices:
      1:
        name: Porch Light
        mac: AA:BB:CC:00:00:11
        wifi_mac: AA:BB:CC:00:01:11
        fw: 1.3.160
        type: 53
        endpoints:
          0: Porch Light
```

Then restart cync-lan.

How to find a bridge's IP:
- The cync-lan log starts every device line with its IP (`192.168.1.50:0x23: ...`).
- Or match the `wifi_mac:` of a device in `cync_mesh.yaml` against your router's DHCP lease list.
- Give your bridges a fixed IP (DHCP reservation). If a bridge's IP changes, its `bridges:` entry no longer matches.

Rules:
- `bridges:` must be a list. Anything else is logged as an ERROR and ignored; the home still loads.
- Entries that are not IP addresses are logged as an ERROR and dropped.
- An IP listed in two homes is logged as an ERROR and ignored for **both** homes.
- You do not need to list every Wi-Fi device. A device that is not listed falls back to signals c and d.
- **Get it right.** A bridge listed under the wrong home is trusted as that home. A command for device 3 of that home
  would then most likely reach device 3 of the bridge's real home instead.

`CYNC_TCP_WHITELIST` still applies to all homes together.

## Connection limit
`CYNC_MAX_TCP_CONN` (default 8) limits how many Wi-Fi devices hold a connection to cync-lan. One or two per home are
enough: every connected device relays its whole Bluetooth mesh, and the devices that are turned away keep working
through it.

- **One home:** the limit is the total, as before.
- **Several homes:** the limit counts **per home**. With the default, each home can have up to 8 bridges (4 homes: up
  to 32 connections). With one shared limit, the first devices to reconnect, often all from one home, took
  every slot and left another home with no bridge at all (seen on a 4-home install with about 100 Wi-Fi devices).
- The home is known when the device connects, from the `switch_id` in its first packet (or a `bridges:` entry).
- A device whose home is not known when it connects (no `switch_id` match, e.g. a config exported before this
  version) is admitted while all bridges together are fewer than `CYNC_MAX_TCP_CONN` x the number of homes. Such
  bridges are placed in their home a little later (signal d), so one home can still end up with more than its share
  and another with none. **Re-export** so every bridge is placed when it connects.

A device that is turned away logs (once every 20 attempts):
```
192.168.1.77::can connect: CyncLAN server max (8/8) TCP connections for Cync home 'House' (123456789) reached, rejecting new connection...
192.168.1.78::can connect: CyncLAN server max (24/24) TCP connections in total (8 x 3 homes; this bridge's home is not known yet) reached, rejecting new connection...
```

**Bridges need their real IP.** cync-lan tracks connections by the device's IP address. If something between the
devices and cync-lan rewrites the source address (Docker Desktop on Windows or macOS, some port forwards and
reverse proxies), every device looks like the same IP and each new connection replaces the previous one. Run
cync-lan with host networking on Linux, or anywhere the devices' own IPs reach it.

## Log lines
These are the lines to look for. Values below are fake. Each device line starts with the bridge's IP.

**Config loaded** (INFO, only with more than one home):
```
CyncLAN:start: 63 devices in 3 Cync homes: 'House' (123456789): 51, 'Cabin' (234567890): 6, 'Office' (345678901): 6
```

**Queue id** (every 0x23 packet: INFO with several homes, DEBUG with one). The text after the number says what it
matched:
```
192.168.1.50:0x23: 0x23 queue id 0x075bcd15 (123456789) equals the id of home 'House' (123456789)
192.168.1.50:0x23: 0x23 queue id 0x3ade68b1 (987654321) equals the switch_id of device 'Kitchen Light' (1) in home 'House' (123456789)
192.168.1.60:0x23: 0x23 queue id 0x0012d687 (1234567) matches no home id and no device switch_id
192.168.1.51:0x23: 0x23 queue id 0x075bcd15 (123456789) equals the id of home 'House' (123456789) (home already decided by bridges)
```
"is ambiguous, ..." means the number matched more than one home; nothing is picked then.
"(home already decided by ...)" means an earlier signal had already picked the home. Compare the two: if they name
different homes, please report it (see below).

With debug logging the same bytes also appear as `Device IDENTIFICATION KEY: '07 5b cd 15'`.

**Home picked from the `bridges:` list** (INFO, at connect):
```
192.168.1.50: Cync home: 'House' (123456789) (192.168.1.50 is in the 'bridges:' list of home 'House' (123456789))
```

**Home worked out later**. The word after "by" is the signal: `queue_id` (INFO) or `fingerprint` (WARNING, because it
is inferred from ids only; check the evidence, then add `bridges:` to make it certain):
```
192.168.1.50: Cync home resolved to 'House' (123456789) by queue_id: queue id 123456789 equals the id of home 'House' (123456789)
192.168.1.52: Cync home resolved to 'House' (123456789) by fingerprint: all 51 reported id(s) (bridge id 4, type 53) are in home 'House' (123456789), which has 0 configured id(s) that were not reported; ruled out: 'Cabin' (234567890) lacks reported id(s) 7-51; 'Office' (345678901) lacks reported id(s) 7-51. This is inferred from device ids. If it is the wrong home (for example devices were added after the last export), add 192.168.1.52 to the right home's 'bridges:' list in cync_mesh.yaml (see docs/multi_home.md)
```

**Home could not be worked out** (WARNING, once per connection):
```
192.168.1.60:0x73: Could not work out which Cync home bridge 192.168.1.60 belongs to: the device ids it reports fit several homes: 'House' (123456789), 'Cabin' (234567890). Its 0x23 queue id is 0x0012d687 (1234567), which matches no device switch_id in the config. Until this is resolved the bridge is not used for commands. Fix: re-export the config from the cloud (the export writes each Wi-Fi device's switch_id, which identifies the bridge from its first packet), then restart. If that does not help, add its IP to the right home in cync_mesh.yaml, e.g. 'bridges: ["192.168.1.60"]' under that home (see docs/multi_home.md).
```
The homes named are the ones still possible. If you added devices since the last export, the right home can look
like it is missing ids; it is still named here as long as the evidence does not clearly rule it out.

**A home has no bridge** (WARNING, see the next section):
```
nCync:home_grace: No TCP bridge for Cync home 'Cabin' (234567890) after 30 seconds: its 6 device(s) are marked offline and commands to them are dropped until one of its Wi-Fi devices connects. ...
```

When no single home has every id the bridge reported (the config is probably older than the account), the first part
reads `no single home in the config has every device id it reports (possible homes: ...)` instead.

**A command could not be sent** (WARNING once per outage, then DEBUG until a bridge of that home connects):
```
... no TCP bridge connected for Cync home 'Cabin' (234567890), command for 'Porch Light' dropped (see docs/multi_home.md); further dropped commands for this home are logged at DEBUG until a bridge connects
```

**Config problems** (ERROR at startup, the rest of the config still loads):
```
parse_config: Home 'Cabin' has a non-numeric 'id' ('abc'), skipping the whole home. Re-export the config or fix the id.
parse_config: Home 'Copy of House' has the same 'id' (123456789) as home 'House', skipping 'Copy of House'
parse_config: Home 'Cabin': 'bridges:' must be a list of IP addresses, got str ('192.168.1.60'), ignoring it
parse_config: Home 'Cabin': 'bridges:' entry 'cabin-plug' is not an IP address, ignoring it
parse_config: Bridge IP 192.168.1.60 is listed in 'bridges:' of both home 'House' and 'Cabin'; it will be ignored for both, keep it in one home only
```
A bad `switch_id:` is logged as a WARNING and ignored; the device still loads.

## No bridge in a home (grace period)
Each home with devices has its own timer. It starts when cync-lan starts, and again when the last bridge of a home
disconnects. It stops as soon as a bridge of that home is connected and its home is known.

If the timer runs out, cync-lan logs the WARNING shown above and marks that home's devices offline in Home Assistant.
Commands to them are dropped (with a WARNING) until a bridge of that home connects. Devices come back online when a
bridge reports them.

| variable | meaning | default |
|---|---|---|
| `CYNC_HOME_NO_BRIDGE_GRACE_SECS` | seconds a home may be without a bridge before the WARNING and offline marking. `0` turns it off. Unset or bad values use the default. | `30` |

Common causes: that home's devices are not DNS-redirected to cync-lan, they are blocked by `CYNC_TCP_WHITELIST` or
`CYNC_MAX_TCP_CONN`, or a bridge is connected but its home could not be worked out (then there is also the
"Could not work out" WARNING).

## Re-exporting the config
- Re-export after adding or removing devices in the Cync app. A stale config makes signal d less reliable (see
  [signal d](#d-fingerprint-of-the-reported-ids-weak-inferred)) and new devices do not show up in Home Assistant.
- The cloud export now writes `switch_id:` for devices that have a `switchID` in the cloud (every Wi-Fi device).
  It is what signal c matches, so **re-export once after upgrading if you have more than one home.** Single-home
  installs do not need it.
- When the export writes a new `cync_mesh.yaml`, each home's `bridges:` list from the existing file is copied into
  the new one. Homes are matched by `id`, so renaming a home in the app does not lose it. The log says
  `Kept the 'bridges:' list of N home(s) from the existing config`. This also happens when
  `CYNC_OVERWRITE_CONFIG_FILE` is `no` and the export goes to a numbered file.
- If the existing file cannot be read, a WARNING says so and you need to re-add `bridges:` by hand.
- Home `id` must be a number. A quoted number (`id: "123456789"`) is accepted.

## Single-home installs
Nothing to configure. The bytes sent to devices are the same as before. You may notice:
- one WARNING (it was a debug line) the first time a command is dropped because no bridge is connected, then debug
  lines until a bridge connects again;
- the no-bridge WARNING after 30 s when no bridge is connected. Devices are then marked offline. Set
  `CYNC_HOME_NO_BRIDGE_GRACE_SECS=0` to turn this off.

## Other changes
- MITM log files are named after the home and device: `mitm_dev_<home_id>-<device_id>-<date>.log` (was
  `mitm_dev_<device_id>-<date>.log`). Two homes' bridges with the same id no longer share one file.

## Please report: other device types
The queue id = `switch_id` rule is confirmed on type 53 switches and type 137 bulbs. If you have other Wi-Fi devices (bulbs,
plugs, light strips, other switch models), your logs help:

1. Re-export the config with this version, start cync-lan (INFO logging is enough) and let your devices connect.
2. Find the `0x23 queue id` lines.
3. If a line says `matches no home id and no device switch_id` for a device that is in your config with a
   `switch_id:`, open an issue at https://github.com/baudneo/cync-lan/issues with that line, the device's `type:`
   and `fw:`, and whether the number equals any `switch_id:` or home `id:` in your file.

Replace IP and MAC addresses if you like. Do not paste your `access_key` or account details.

See also: [protocol reference](./protocol.md) (open question 2), `src/cync_lan/devices/registry.py`.
