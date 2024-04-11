# pycync_lan (cync_lan)

:warning: **DNS redirection required** :warning:

Async MQTT LAN controller for Cync/C by GE devices. **Local** only control of **most** Cync devices via Home Assistant.

**This is a work in progress, and may not work for all devices.** See [known devices](docs/known_devices.md) for more information.

Forked from [cync-lan](https://github.com/iburistu/cync-lan) and [cync2mqtt](https://github.com/juanboro/cync2mqtt) - All credit to [iburistu](https://github.com/iburistu) and [juanboro](https://github.com/juanboro)

## Prerequisites

- MQTT broker (I recommend EMQX)
- Cync account with devices added and configured
- A minimum of 1, non battery powered, Wi-Fi Cync device to act as the TCP <-> BT bridge. I recommend a plug or always powered wifi bulb (wired switch not tested yet) - *The wifi device' can control BT only bulbs*
- Create self-signed SSL certs using `CN=*.xlink.cn` for the server. You can use the `create_certs.sh` script.
- Export devices from the Cync cloud to a YAML file; first export required cync email, password and a OTP emailed to you.
- DNS override/redirection for `cm.gelighting.com` or `cm-ge.xlink.cn` to a local host that will run `cync-lan`.

The only way local control will work is by re-routing DNS traffic from the Cync cloud server to your local network, you'll need some 
way to override DNS - a local DNS server; OPNsense/pfSense running unbound, Pi-Hole, etc. See the [DNS docs](docs/DNS.md) for more information.

## Installation
Please see [Install docs](./docs/INSTALL.md) for more information.

## Re-routing / Overriding DNS
There are detailed instructions for Opnsense and Pi-hole. See [DNS docs](docs/DNS.md) for more information.

:warning: **After freshly redirecting DNS: Devices that are currently talking to Cync cloud will need to be power cycled before they make a DNS request and connect to the local server.** :warning:

As long as your DNS is correctly re-routed, you should be able to start the server and see devices connecting to it.
If you do not see any Cync devices connecting after power cycling them, you may need to check your DNS re-routing.

### Testing DNS override
If you set up **network wide** DNS override, you can use `dig` or `nslookup` to test 
if the DNS override is working correctly.

 ```bash
# Older firmware
dig cm-ge.xlink.cn

# Newer firmware
dig cm.gelighting.com

# Example output with a local A record returned
; <<>> DiG 9.18.24 <<>> cm.gelighting.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56237
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;cm.gelighting.com.             IN      A

;; ANSWER SECTION:
cm.gelighting.com.      3600    IN      A       10.0.1.9 <---- Overridden to a local machine running cync-lan

;; Query time: 0 msec
;; SERVER: 10.0.1.1#53(10.0.1.1) (UDP)
;; WHEN: Fri Mar 29 08:26:51 MDT 2024
;; MSG SIZE  rcvd: 62
```

:warning: **If you are using selective DNS override via `views` in `unbound`, and you did not set up an override for the IP of the machine running `dig`,
the command will return the Cync cloud IP. This is normal.**

## Config file
:warning: **The config file will override any environment variables set.** :warning:

**It is required to query the Cync cloud API to export all your homes and the devices in each home.** 
This requires your email, password and the code that will be emailed to you during export.

If you add or remove devices, you *should* re-export the config file and restart the server.

See the example [config file](./cync_mesh_example.yaml)

### Export config from Cync cloud API
There is an `export` sub command that will query the Cync cloud API and export the devices to a YAML file.

```bash
# If you used --save-auth in a previous export command, you can use --auth to 
# provide the auth file to skip asking for your credentials and OTP
python3 cync-lan.py export ./cync_mesh.yaml
```

### Manually adding devices
To manually add devices to the config file, look at the example and follow the template. 
From what I have seen the device ID starts at 1 and increments by 1 for each device added to the "home" 
(it follows the order you added the bulbs).

*It is unknown how removing a device and adding a device may affect the ID number, YMMV. 
Be careful when manually adding devices.*

:warning: By manually adding, I mean you added a device via the app and did not re-export a new config.

## CLI arguments

You can always supply `--help` to the cync-lan.py script to get a breakdown. Please see the [sub-command docs](./docs/cync-lan%20sub-commands.md) for more information.

## Env Vars

| Variable     | Description                                  | Default                            |
|--------------|----------------------------------------------|------------------------------------|
| `MQTT_URL`   | URL of MQTT broker                           | `mqtt://homeassistant.local:1883/` |
| `CYNC_DEBUG` | Enable debug logging                         | `0`                                |
| `CYNC_CERT`  | Path to cert file                            | `certs/server.pem`                 |
| `CYNC_KEY`   | Path to key file                             | `certs/server.key`                 |
| `CYNC_PORT`  | Port to listen on                            | `23779`                            |
| `CYNC_HOST`  | Host to listen on                            | `0.0.0.0`                          |
| `CYNC_TOPIC` | MQTT topic                                   | `cync_lan`                         |
| `HASS_TOPIC` | Home Assistant topic                         | `homeassistant`                    |
| `MESH_CHECK` | Interval to check for online/offline devices | `30`                               |

## Controlling devices

Devices are controlled by MQTT messages. This was designed to be used with Home Assistant, but you can use 
any MQTT client to send messages to the MQTT broker.

**Please see [Home Assistant MQTT documentation](https://www.home-assistant.io/integrations/light.mqtt/#json-schema) 
for more information on JSON payloads.** This repo will try to stay up to date with the latest Home Assistant MQTT JSON schema.

## Home Assistant

This script uses the MQTT discovery mechanism in Home Assistant to automatically add devices.
You can control the Home Assistant MQTT topic via the environment variable `HASS_TOPIC`.

## Debugging / socat

If the devices are not responding to commands, it's likely that the TCP communication on your
device is different. You can either open an issue and I can walk you through getting good debug logs, 
or you can use `socat` to inspect the traffic of the device communicating with the cloud server in real-time yourself by running:

```bash
# Older firmware devices
socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:34.73.130.191:23779,verify=0
# Newer firmware devices (Notice the last IP change)
sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0
```
In `dump.txt` you will see the back-and-forth communication between the device and the cloud server.
`>` is device to server, `<` is server to device.

# Firewall
Once the devices are local, they must be able to initiate a connection to the cync-lan server. If you block them from internet, don't forget to allow them to connect to the cync-lan server.

# Power cycle devices after DNS re-route
Devices make a DNS query on first startup (or after a network loss, like AP reboot) - 
you need to power cycle all devices that are currently connected to the Cync cloud servers 
before they request a new DNS record and will connect to the local controller.
