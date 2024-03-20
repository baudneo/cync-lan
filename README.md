# pycync_lan (cync_lan)

Async MQTT LAN controller for CYNC/C by GE devices. **Local** only control of **most** of your cync devices via Home Assistant.

**This is a work in progress, and may not work for all devices.** See [known devices](docs/known_devices.md) for more information.

:warning: **DNS redirection required** :warning:

Forked from [cync-lan](https://github.com/iburistu/cync-lan) and [cync2mqtt](https://github.com/juanboro/cync2mqtt) - All credit to [iburistu](https://github.com/iburistu) and [juanboro](https://github.com/juanboro)

## Prerequisites:

- Create self-signed SSL certs using `CN=*.xlink.cn` for the server. You can use the `create_certs.sh` script or the `cync-lan.py certs` sub-command to do so.
- 1+ non battery powered Wi-Fi Cync device to act as the TCP <-> BT bridge. I recommend a plug or always powered wifi bulb (wired switch not tested yet) - *The wifi device can control BT only bulbs*

As this works by re-routing DNS traffic from the Cync cloud server to your local network, you'll need some 
way to override DNS - a local DNS server; OPNsense/pfSense running unbound, Pi-Hole, or a `/etc/hosts` file on your router 
will work.

See the [DNS docs](docs/DNS.md) for more information.

## Installation:

System packages you will need:
- `openssl`
- `git`
- `python3`
- `python3-venv`
- `python3-pip`
- `python3-setuptools`
- You may also want `dig` and `socat` for **debugging**.

```bash
# Create dir for project and venv
mkdir ~/cync-lan && cd ~/cync-lan
python3 -m venv venv
# activate the venv
source ~/cync-lan/venv/bin/activate

# create self-signed cert
https://raw.githubusercontent.com/baudneo/cync-lan/python/create_certs.sh
bash ./create_certs.sh

# install deps
pip install pyyaml requests cryptography pydotenv uvloop
pip install git+https://github.com/Yakifo/amqtt.git

# wget file
wget https://raw.githubusercontent.com/baudneo/cync-lan/python/src/cync-lan.py

# Run script to export cloud device config to ./cync_mesh.yaml
# It will ask you for email, password and the OTP emailed to you.
# --save-auth will save the auth data to its own file that you can supply to the export command using --auth <auth file>
python3 ~/cync-lan/cync-lan.py export ~/cync-lan/cync_mesh.yaml --save-auth

# edit cync_mesh.yaml to put it values for your MQTT broker

# Run the script to start the server, provide it with the path to the config file
# You can add --debug to enable debug logging
python3 ~/cync-lan/cync-lan.py run ~/cync-lan/cync_mesh.yaml
```

## Env Vars
These are for the future docker image.

| Variable     | Description          | Default                            |
|--------------|----------------------|------------------------------------|
| `MQTT_URL`   | URL of MQTT broker   | `mqtt://homeassistant.local:1883/` |
| `CYNC_DEBUG` | Enable debug logging | `True`                             |
| `CYNC_CERT`  | Path to cert file    | `certs/server.pem`                 |
| `CYNC_KEY`   | Path to key file     | `certs/server.key`                 |
| `CYNC_PORT`  | Port to listen on    | `23779`                            |
| `CYNC_HOST`  | Host to listen on    | `0.0.0.0`                          |


## Re-routing / Overriding DNS
See [DNS docs](docs/DNS.md) for more information.

## Launching the server / MQTT client
:warning: **If you just redirected DNS: Devices that are currently talking to Cync cloud will need to be power cycled before they make a DNS request.** :warning:

As long as your DNS is correctly re-routed, you should be able to start the server and see devices connecting to it.
If you do not see any cync devices connecting after power cycling, you may need to check your DNS re-routing.
```bash
source ~/cync-lan/venv/bin/activate
python3 ~/cync-lan/cync-lan.py run ~/cync-lan/cync_mesh.yaml
```

## Config file
For the best user experiance, query the Cync cloud API to export all your homes and the devices in each home. 
This requires your email, password and the code that will be emailed to you during export.

If you add or remove devices, you can re-export the config file and restart the server.

See the example [config file](./cync_mesh_example.yaml)


## Controlling devices

Devices are controlled by MQTT messages. This was designed to be used with home assistant, but you can use any MQTT client to send messages to the server.

**Please see Home Assistant MQTT documentation for more information on topics and payloads.**

## Home Assistant

This script uses the MQTT discovery mechanism in Home Assistant to automatically add devices to the UI.
You can control the home assistant topic in the config file.

## Debugging / socat

If the devices don't seem to responding to commands, it's likely that the TCP communication on your
device is different than mine. Please open an issue and I can walk you through getting me good debug logs so 
I can add support.

You can inspect the traffic of the device communicating 
with the cloud server in real-time by running:

### Older firmware devices

```bash
socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:34.73.130.191:23779,verify=0
```

### Newer firmware devices

*Notice the last IP change*
```bash
sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0
```

in `dump.txt` you will see the back-and-forth communication between the device and the cloud server. ">" is device to server, "<" is server to device.

Also make sure to check that your DNS re-route is actually routing to your local network. You can check by using `dig`:

### Older firmware

```bash
dig cm-ge.xlink.cn
```

### Newer firmware

```bash
dig cm.gelighting.com
```

You should see an A record for your local network. If not, your DNS is not set up correctly.

**If you are using selective DNS override via `views` in `unbound`, and you did not set up an override for your PC's IP,
your dig command will still return the cync cloud IP. This is normal.**


# Power cycle devices after DNS re-route
The devices make 1 DNS query on first startup (or after a network loss, like AP reboot) - 
you need to cycle power all devices that are currently connected to the cync cloud servers 
before they request a new DNS record.
