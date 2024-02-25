# pycync_lan

Async MQTT LAN controller for CYNC devices. **DNS redirection required**

Forked from [cync-lan](https://github.com/iburistu/cync-lan) All credit to [iburistu](https://github.com/iburistu)

## Prerequisites:

Because this works by re-routing DNS traffic to your local network, you'll need some 
way to route DNS - a local DNS server, Pi-Hole, or `/etc/hosts` file on your router 
will work. You'll also need `openssl` on your system. You may also need `dig` and `socat` for **debugging**.

See the [Re-routing DNS](#re-routing-dns) section for more information.

## Installation:

Make sure you have `openssl` system package installed first.

```bash

# Create dir for project and venv
mkdir ~/cync-lan && cd ~/cync-lan
python3 -m venv venv
# activate the venv
source ./venv/bin/activate

# create self signed cert
https://raw.githubusercontent.com/baudneo/cync-lan/python/create_certs.sh
bash ./create_certs.sh

# install deps
pip install uvloop
# wget file
wget https://raw.githubusercontent.com/baudneo/cync-lan/python/src/cync-lan.py

# Run script
python3 ./cync-lan.py
# ctrl+C to stop
```

## Env Vars

| Variable | Description | Default            |
|----------|-------------|--------------------|
| `CYNC_DEBUG` | Enable debug logging | `True`           |
| `CYNC_CERT` | Path to cert file | `certs/server.pem` |
| `CYNC_KEY` | Path to key file | `certs/server.key` |


## Re-routing DNS

There are changes in newer firmware! Check your DNS logs and search for `xlink.cn`, if you see DNS requests then you have some older devices. If you dont see any devices for `xlink.cn` search for `cm.gelighting.com`, if you see devices, thats newer firmware.

You need to point the cloud server domain to a local IP on your network. This server masquerades as the cloud TCP server.

Older firmware:
 - `cm-ge.xlink.cn`

Newer firmware:
 - `cm.gelighting.com`


## Launching the server

I found it easiest to first start the server, then turn on/plug in/power cycle the devices.

:warning: **Devices need to be power cycled before they will connect to the LAN server**

To start the server, make sure the venv is active:

```bash
cd ~/cync-lan
source ./venv/bin/activate
python3 ./cync-lan.py
```

If you're correctly routing the DNS traffic, you should see a new connection appearing in the logs.

## Controlling devices:

**CURRENTLY NOT IMPLEMENTED**

Devices are controlled by MQTT.


## Debugging / socat

If the commands do not seem to be working, it's likely that the TCP communication on your
device is different than mine. You can inspect the traffic of the device communicating 
with the cloud server in real-time by running:

```bash
# You can change the cert and key path to an absolute path if you want
# otherwise run from the same directory as the certs dir (~/cync-lan).

# To log the traffic to a file
sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0

# To log the traffic to stdout
sudo socat -d -d -x -v ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0
```

in `dump.txt` you will see the back-and-forth communication between the device and the cloud server. ">" is device to server, "<" is server to device.

### Older firmware devices

```bash
socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:34.73.130.191:23779,verify=0
```

### Newer firmware devices

*Notice the last IP change*
```bash
sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0
```

The TCP data will be streamed to `dump.txt` where you can observe the back-and-forth messaging. You may need to modify the different CONSTS in the `cync-lan.py` file to match the device's communication.

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

# Power cycle devices after starting server
The devices make the DNS query on startup - you need to cycle power for all devices on the network for them to use your local server.
