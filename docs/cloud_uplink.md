# Cloud uplink: keep the Cync app as a viewer, cync-lan as the brain

With the DNS redirect every Cync device talks to cync-lan, so the Cync cloud sees none of them and the app shows them all
as unavailable. Two opt-in options give the app a live view again without handing control back to the cloud.

| env (HA app option) | default | what it does |
|---|---|---|
| `CYNC_CLOUD_UPLINK` (`cloud_uplink`) | off | per home, ONE bridge is relayed to the real Cync cloud (MITM mode). It still reports every mesh device's state to cync-lan, and the cloud (so the app) sees the whole home through it. All other bridges stay local and carry every command from Home Assistant. |
| `CYNC_APP_PROXY` (`app_proxy`) | off | a phone the DNS redirect sends to cync-lan is relayed to the real cloud instead of being closed, so the app works on your own Wi-Fi. With `CYNC_APP_MITM_LOGGING` the app's traffic is logged (`mitm_logs/`), which is how its commands (for example creating a group) get captured. |

## Which bridge is the uplink
1. The home's `cloud_uplink:` list in `cync_mesh.yaml`, if you wrote one (device ids; kept when the config is re-exported):
   ```yaml
   exported_homes:
     Casita 2:
       cloud_uplink: [30, 33]
   ```
2. Otherwise the home's **multi-way (3-way / 4-way auxiliary) switches**: in the Cync app a switch set to multi-way keeps
   its own load on and only relays presses to the switch that drives the light, so nobody needs to control it and it is
   always powered. The export marks them `multi_way: true`. The app stores this as a cloud-only device setting whose JSON
   key name is not confirmed yet: the export logs every cloud device field name (INFO, names only) and treats any field
   named like "multiWay" as the flag. If no device gets `multi_way: true`, send that log line in an issue, or list the ids
   by hand in `cloud_uplink:`.
3. No candidate: the home has no uplink and nothing changes.

The first candidate to connect becomes the uplink; one per home. Its "MITM mode" switch in HA turns ON (retained, so it
comes back after a restart). Turning the option off later does not turn that switch off: turn it off in HA.

## Limits
- An uplink bridge is not used for commands from Home Assistant (no MITM bridge is). Keep at least one other Wi-Fi device
  in the home.
- Commands from the app go through the cloud and the uplink bridge; cync-lan sees the resulting state changes, so HA stays
  in sync, but the cloud is in the loop for those commands. Use HA for anything that must work without the internet.
- Signing in and adding new devices always need the real cloud (the app's account API checks certificates).
