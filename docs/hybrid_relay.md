# Hybrid relay (experimental): cloud-visible AND locally controlled

`CYNC_HYBRID_RELAY` (HA app option `hybrid_relay`): comma separated device ids as in the MQTT topics,
`<home_id>-<device_id>` (e.g. `1754061898-12`), or `all`. Empty = off.

The Cync cloud shows a Wi-Fi device as online only while that device has its own connection to the cloud: one bridge
reporting the whole mesh is not enough (tested 2026-11-04). A device in hybrid relay keeps one connection, to cync-lan,
which passes it on to the real cloud like MITM mode does, but cync-lan also keeps sending its own commands down it.

- Device -> cloud: forwarded packet by packet. Replies to cync-lan's own commands are NOT forwarded (the cloud never
  sent those commands): 0x73 control replies whose control id cync-lan is waiting for, and 0x7B packets with msg id
  `00 00 00` (cync-lan's 0x73 use msg id 0) within 10 s of a command. cync-lan acks those itself, as in local mode.
- Cloud -> device: passed on as whole packets, under the write lock, so a cync-lan command never lands inside one.
- cync-lan still reads every packet from the device, so HA follows changes made in the app.
- The cloud acks everything else (cync-lan's own acks stay off, as in MITM mode).
- Cloud unreachable when the device (re)connects: that connection runs local-only; hybrid resumes the next time the device
  reconnects. A cloud that closes the connection closes the device session, so it reconnects.
- Listed devices are always admitted, outside the home's `CYNC_MAX_TCP_CONN` bridge limit, and do not take a slot:
  the cloud only shows a device whose own connection is up.
- Turning the device's "MITM mode" switch off in HA also ends hybrid relay for it until cync-lan restarts.

**Confirmed 2026-11-04** on one type 53 switch (Casita 2, Master Shower Lights), with the app proxy on: the app showed it
online and controlled it, HA controlled it locally and followed the app's changes, on the same connection.

Still unconfirmed: whether the device acks cync-lan's 0x73 with a 0x7B that echoes msg id 0, and
whether the cloud's control ids can collide with cync-lan's (a collision would make cync-lan keep one of the cloud's
replies). Watch the MITM log (`mitm_logs/`) and the debug line "hybrid: kept a reply to a cync-lan command".
