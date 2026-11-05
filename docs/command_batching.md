# Command batching (CYNC_CMD_BATCH_MS)

An HA light group (e.g. "Master" = five Cync room lights) fires one command per member within a few milliseconds.
Each command used to go to `CYNC_CMD_BROADCASTS` (2) bridges picked at random, so five rooms went out through up to ten
bridges, each relaying over the BLE mesh at its own pace, and the rooms changed one after another.

With `CYNC_CMD_BATCH_MS` (default 30, HA app option `tuning.command_batch_ms`; 0 = off):
- commands to one home that arrive within the window go through the SAME bridges;
- each of those bridges gets them in ONE write, so the mesh receives the whole burst together.

A single command waits at most the window before it is written. Not batched: commands to a device that has its own
connection (it always gets them directly), and order-sensitive ones (group membership, one bridge, written at once).

Why not one group for everything: a wall switch's own button follows its groups (docs/local_groups.md), so a cross-room
group of wall switches makes every one of them switch the whole group. Batching the room commands keeps each switch on
its own room.
