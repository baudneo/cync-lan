>[!IMPORTANT]
> [DNS redirection REQUIRED](./docs/DNS.md)

# THERE IS NOW A HASS *App* FOR THIS PROJECT!

Huge thanks to [@CodeNeedsCoffee](https://github.com/CodeNeedsCoffee) for the initial work on the App! For the foreseeable future, this project will stick with MQTT. The only way to create HASS devices is MQTT or an integration.

[![Open your Home Assistant instance and show the add App repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbaudneo%2Fhass-addons)

The existing `python` branch will remain for users who prefer a non HASS App setup. However, docker is required and 
manual installation is no longer officially supported.

![GitHub Release](https://img.shields.io/github/v/release/baudneo/cync-lan) 
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/baudneo/cync-lan/container-package-publish.yml) 
![Docker Pulls](https://img.shields.io/docker/pulls/baudneo/cync-lan)

>[!WARNING]
> **DO NOT** contact GE / Savant for troubleshooting while using this project, open issues here and tag @baudneo 
> for fast responses.

Async HTTP/MQTT LAN controller for Cync/C by GE devices. **Local** only control
of **most** Cync devices via MQTT JSON payloads following the Home Assistant MQTT JSON schema. 
This project masquerades as the cloud server, allowing you to control your devices locally.

**This is a work in progress, and may not work for all devices.** 
See [known devices](docs/known_devices.md) for more information. Battery powered devices are currently *not* supported due to them being BTLE only.

Forked from [cync-lan](https://github.com/iburistu/cync-lan) and 
[cync2mqtt](https://github.com/juanboro/cync2mqtt) - All credit to 
[iburistu](https://github.com/iburistu) and 
[juanboro](https://github.com/juanboro)

>[!WARNING]
> It is **HIGHLY** recommended that you do **NOT** do any firmware upgrades to Cync devices after running cync-lan. 
> It is extremely (change 1 param in a constructor or config) easy for Savant to disable this method of local control.
> While new methods may restore functionality, I'd rather not go down that route.

## Prerequisites
- ~~Python 3.9+ (Walrus [:=] operator and `zoneinfo` built-in package used)~~ ;)
- Docker
- A minimum of 1, non battery powered, Wi-Fi (*Direct Connect*) Cync / C by GE device to act as the TCP <-> BT bridge (always on)
- Cync account with devices added
- MQTT broker (I recommend EMQX)
- Export devices from the Cync cloud to a YAML file; first export requires account email, password and an OTP emailed to you
  - After configuring and running the container, navigate to http://127.0.0.1:23778 to export devices from the cloud 
- [DNS override/redirection](./docs/DNS.md) for `cm.gelighting.com`, `cm-sec.gelighting.com` or `cm-ge.xlink.cn` to a local host that will run `cync-lan`
- **Optional:** *[Firewall](#firewall) / routing rules to allow cync devices to talk to `cync-lan`* **(VLANs?)**

>[!NOTE]
> You still need to use your Cync account to add new devices as you acquire them.

---

## Installation

See the [installation](./docs/install.md) docs for more information


>[!IMPORTANT]
> After configuring and running the container, you must visit http://localhost:23778 in order to export your Cync 
> devices from the Cync cloud API. Your Cync account creds are set using an env var in the docker-compose.yaml file, 
> the web app will initiate OTP auth and export homes and each homes device list

---

## Re-routing / Overriding DNS
>[!WARNING] 
> After freshly redirecting DNS: Devices that are currently
> talking to Cync cloud will need to be power cycled before they make
> a DNS request and connect to the local `cync-lan` server.

There are detailed instructions for OPNSense, Pi-hole and Ad-Guard Home. 
See [DNS docs](docs/DNS.md) for more information.

## Tips
See [Tips](docs/tips.md) for more information on how to get the most out of this project.

Also, let me set some expectations:
1. HASS light groups will always have a delay on state changes between each other (set group of cync lights green, they don't all change to green at the same time) 
At the moment, the script receives an MQTT command, sends commands to `x` devices 
and receives a `success` response all within 200 ish ms (0.2 seconds). I don't know
what happens on the device itself, but the TCP <-> BT bridge is not instant, when it really should be. Work continues on improving this.
2. There are no provisions for the Cync app to work with this project, any data sent by the app is black-holed (for now, anyway; MITM proxy to record commands and responses in the future).
3. If I don't own a device, I cant test it, and if I cant test it, I cant support it easily. 
   - If you want a device supported, you will need to set up a debug env and send me logs of the device communicating with the cloud server.
---

## Config file
See the example [config file](./cync_mesh_example.yaml)

### Export config from Cync cloud API

#### **NEW** Web App
By default, the export webserver is started when cync-lan is. Navigate to http://localhost:23778 to access the export web app.

#### CLI
~~There is an `export` sub command~~ **Currently being refactored**.

---

## CLI arguments
You can always supply `--help` to the cync-lan.py script to get a breakdown.

## Env Vars
For the `yes` / `no` value, the user input is cast to a lower case string stripped of spaces:
- Yes answers: "true", "1", "yes", "y", "t", 1, "on", "o"
- No is interpreted as anything other than the yes answers

| Variable                     | Description                                                                                                                 | Default                               | Type |
|------------------------------|-----------------------------------------------------------------------------------------------------------------------------|---------------------------------------|------|
| `CYNC_ENABLE_EXPORTER`       | Start the local device export web app                                                                                       | `yes`                                 | str  |
| `CYNC_ACCOUNT_USERNAME`      | Cync account username (email) *Required* for the export web app                                                             |                                       | str  |
| `CYNC_ACCOUNT_PASSWORD`      | Cync account password *Required* for the export web app                                                                     |                                       | str  |
| `CYNC_OVERWRITE_CONFIG_FILE` | On export, overwrite `cync_mesh.yaml` or use a numbered system: `*_1.yaml`, `*_2.yaml`, etc.                                | `no`                                  | str  |
| `CYNC_MQTT_HOST`             | Host of MQTT broker                                                                                                         | `homeassistant.local`                 | str  |
| `CYNC_MQTT_PORT`             | Port of MQTT broker                                                                                                         | `1883`                                | int  |
| `CYNC_MQTT_USER`             | Username for MQTT broker                                                                                                    |                                       | str  |
| `CYNC_MQTT_PASS`             | Password for MQTT broker                                                                                                    |                                       | str  |
| `CYNC_MQTT_CONN_DELAY`       | Delay between MQTT re-connections (seconds)                                                                                 | `10`                                  | int  |
| `CYNC_MQTT_DEBUG`            | Enable MQTT debug logs even if debug level is set (set to no for less debug level log spam)                                 | `yes`                                 | str  |
| `CYNC_DEBUG`                 | Enable debug logging                                                                                                        | `no`                                  | str  |
| `CYNC_RAW_DEBUG`             | Enable raw binary message debug logging                                                                                     | `no`                                  | str  |
| `CYNC_DEVICE_CERT`           | Path to cert file                                                                                                           | `certs/server.pem`                    | str  |
| `CYNC_DEVICE_KEY`            | Path to key file                                                                                                            | `certs/server.key`                    | str  |
| `CYNC_SRV_HOST`              | Interface to listen on                                                                                                      | `0.0.0.0`                             | str  |
| `CYNC_PORT`                  | Port to listen for Cync devices (Do NOT change, unless you know what you are doing)                                         | `23779`                               | int  |
| `CYNC_EXPORT_HOST`           | Host for export web app                                                                                                     | `{CYNC_SRV_HOST}`                     | str  |
| `CYNC_EXPORT_PORT`           | Port for export web app                                                                                                     | `23778`                               | int  |
| `CYNC_TOPIC`                 | MQTT topic                                                                                                                  | `cync_lan`                            | str  |
| `CYNC_HASS_TOPIC`            | Home Assistant topic                                                                                                        | `homeassistant`                       | str  |
| `CYNC_HASS_STATUS_TOPIC`     | HASS status topic for birth / will                                                                                          | `status`                              | str  |
| `CYNC_HASS_BIRTH_MSG`        | HASS birth message                                                                                                          | `online`                              | str  |
| `CYNC_HASS_WILL_MSG`         | HASS will message                                                                                                           | `offline`                             | str  |
| `CYNC_CMD_BROADCASTS`        | Number of WiFi devices to send state *change* commands to (2+ offers noticeable command response improvements)              | `2`                                   | int  |
| `CYNC_MAX_TCP_CONN`          | Maximum WiFi devices allowed to connect at a time (keep down log spam, unneccesary load)                                    | `8`                                   | int  |
| `CYNC_TCP_WHITELIST`         | Comma separated string of allowed IPs (keep down log spam, unneccesary load, restrict to 'always-on' devices)               | Allow ALL IPs                         | str  |
| `CYNC_TCP_BLACKHOLE_DELAY`   | If a non-whitelisted IP *OR* max devices reached connects, how long to keep the connection open before closing it (seconds) | `14.95`                               | int  |
| `CYNC_BASE_DIR`              | Base directory for **ALL** files.                                                                                           | `/root/cync-lan`                      | str  |
| `CYNC_CFGAPPEND_DIR`         | Directory for persistent files (config, uuid, etc.) This is **appended** to `CYNC_BASE_DIR`                                 | `/config`                             | str  |
| `CYNC_STATIC_DIR`            | Absolute path to where the index.html and css/js dirs/files are stored                                                      | `{CYNC_BASE_DIR}/www`                 | str  |
| `CYNC_CONFIG_DIR`            | Absolute path to where the persistent files are stored (cync_mesh.yaml, uuid.txt and .cloud_auth.yaml)                      | `{CYNC_BASE_DIR}{CYNC_CFGAPPEND_DIR}` | str  |


## Controlling devices
Devices are controlled by JSON MQTT messages. This was designed to be used 
with Home Assistant, but you can use any MQTT client to send messages 
to the MQTT broker.

**Please see [Home Assistant MQTT documentation](https://www.home-assistant.io/integrations/light.mqtt/#json-schema) 
for more information on JSON payloads.** This repo will try to stay up to
date with the latest Home Assistant MQTT JSON schema.

## Home Assistant
Cync-LAN uses the MQTT discovery mechanism in Home Assistant to 
automatically add devices. You can control the Home Assistant MQTT 
topic via the environment variable `CYNC_HASS_TOPIC` (default: `homeassistant`).

## Debugging / socat
If your devices are not responding to commands, it's likely that the TCP
communication on the device is different. You can either open an issue 
and I can walk you through getting good debug logs, or you can use 
`socat` to inspect (MITM) the traffic of the device communicating with the 
cloud server in real-time yourself by running:

```bash
# make sure to create the self-signed certs first (they will be located in ./certs/ dir)
# Older firmware devices
socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:34.73.130.191:23779,verify=0
# Newer firmware devices (Notice the last IP change)
sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0
```
In `dump.txt` you will see the back-and-forth communication between the device and the cloud server.
`>` is device to server, `<` is server to device.

>[!IMPORTANT]
> I am planning on writing a MITM mode that will allow a user to capture command sequences in real-time, greatly reducing the manual labour required to debug and add unknown devices.

# Firewall
Once the devices are local, they must be able to initiate a connection to 
the `cync-lan` server. If you block them from the internet, don't forget to 
allow them to connect to the `cync-lan` server (VLANs?).

## OPNsense Example
Please see the [example](./docs/troubleshooting.md#opnsense-firewall-example)
in the troubleshooting docs.

# Power cycle devices after DNS re-route
Devices make a DNS query on first startup (or after a network loss,
like AP reboot) - you need to power cycle all devices that are currently 
connected to the Cync cloud servers before they request a new DNS record 
and will connect to the local `cync-lan` server.

# Troubleshooting
If you are having issues, please see the 
[Troubleshooting docs](docs/troubleshooting.md) for more information.

# Buy devices to be supported
If you really want a device added, [purchase it from this Amazon wish list](https://www.amazon.ca/registries/gl/guest-view/270SHDZQLXRU8), 
and it will be sent to me. I will add support ASAP.

