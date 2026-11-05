# Local groups (cync-lan puts the group on the switches)

> **A switch's own button follows its groups.** Found 2026-11-05 with a 9-switch "Master Suite" group across five
> rooms: after the sync, pressing ANY of those wall switches turned the whole suite on / off. That is why the Cync app
> keeps rooms small: each room is what its switches control. Only put devices in a local group whose buttons nobody
> presses, or that should control the whole group: bulbs, plugs, 3-way auxiliary switches, or switches that already
> share one load. For "one tap turns the whole suite", use an HA light group of the Cync ROOM lights instead (one packet
> per room).

**Confirmed 2026-11-05** on two type 53 switches in different rooms: after *Sync to switches* each reported the new group
next to its room (`0x80fe, 0x800a` and `0x80fe, 0x8008`).

A Cync room or group is a group address (`0x80xx`) stored on each member switch; one command to that address switches
every member at once. The Cync app creates them; cync-lan can now do it too, for groups the app cannot make (e.g. one
group across several rooms, like a whole master suite). See docs/protocol.md, "Group membership".

```yaml
exported_homes:
  Casita 2:
    local_groups:
      32990:                 # 0x80DE; ids 32769-33022 (0x8001-0x80FE), not used by the Cync account
        name: Master Suite
        members: [12, 13, 15, 23, 25, 26, 27, 28, 29]
```
- Kept when the config is re-exported. Pick ids from the top (`0x80FE` down): the app allocates upwards.
- Each local group gets an HA light (one packet for the whole group) and two buttons on its HA device:
  **Sync to switches** (sends the joins) and **Remove from switches** (sends the leaves). Press Sync after creating or
  changing a group; remove a member from the config only after pressing Remove (or it keeps the group).
- The join mimics the app: a member that is in a room leaves it, joins it again with flag `0x87`, then joins the group.
- The Cync account does not know these groups. Editing a member's room in the app may rewrite its group list: press Sync
  again. A switch holds at most 8 groups (a room plus a few groups is fine).
- Membership commands go through any bridge of the home, 0.4 s apart. Watch the log for
  `device <id> groups: 0x80de, 0x8008` (the switch's own report) to confirm each join.
