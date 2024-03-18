# pycync_lan (cync_lan)

Async MQTT LAN controller for CYNC devices. 

:warning: **DNS redirection required** :warning:

Forked from [cync-lan](https://github.com/iburistu/cync-lan) and [cync2mqtt](https://github.com/juanboro/cync2mqtt) 
All credit to [iburistu](https://github.com/iburistu) and [juanboro](https://github.com/juanboro)

## Prerequisites:

Because this works by re-routing DNS traffic to your local network, you'll need some 
way to route DNS - a local DNS server (OPNsense, pfSense running unbound), Pi-Hole, or `/etc/hosts` file on your router 
will work. You'll also need `openssl` on your system. You may also need `dig` and `socat` for **debugging**.

See the [Re-routing DNS](#re-routing-dns) section for more information.

## Installation:

Make sure you have `openssl` and `git` system package installed first.

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
pip install pyyaml requests cryptography pydotenv
pip install uvloop
pip install git+https://github.com/Yakifo/amqtt.git

# wget file
wget https://raw.githubusercontent.com/baudneo/cync-lan/python/src/cync-lan.py

# Run script to export cloud device config to ./cync_mesh.yaml
# It will ask you for email, password and the OTP emailed to you.
python3 ~/cync-lan/cync-lan.py export ~/cync-lan/cync_mesh.yaml

# edit cync_mesh.yaml to put it values for your MQTT broker

# Run the script to start the server, provide it with the path to the config file
python3 ~/cync-lan/cync-lan.py run ~/cync-lan/cync_mesh.yaml
```

## Env Vars
You can also supply a .env file to `pydotenv` using the `run <config file> --env <env file>` command line parameter.
This is handy for docker environments.

| Variable | Description | Default            |
|----------|-------------|--------------------|
| `CYNC_DEBUG` | Enable debug logging | `True`           |
| `CYNC_CERT` | Path to cert file | `certs/server.pem` |
| `CYNC_KEY` | Path to key file | `certs/server.key` |
| `CYNC_PORT` | Port to listen on | `23779` |
| `CYNC_HOST` | Host to listen on | `0.0.0.0` |


## Re-routing DNS

There are changes in newer firmware! Check your DNS logs and search for `xlink.cn`, if you see DNS requests then you have some older devices. If you dont see any devices for `xlink.cn` search for `cm.gelighting.com`, if you see devices, thats newer firmware.

You need to point the cloud server domain to a local IP on your network. This server masquerades as the cloud TCP server.

Older firmware:
 - `cm-ge.xlink.cn`

Newer firmware:
 - `cm.gelighting.com`

### Selective DNS routing based on requesting device using Unbound DNS
If you run bind9 or unbound, you can use 'views' to selectively route DNS requests based on the requesting device. This is useful if you have a mix of older and newer firmware devices, or you only want certain devices to be rerouted.


The following example will reroute DNS requests for `cm.gelighting.com` to `10.0.1.9` for the device `10.0.1.167`.
`local-zone` is your DNS domain (.local, .lan, .whatever). Notice there is no `.`!!.

I use OPNsense and this config is placed in `Services`>`Unbound DNS`>`Advanced Options`.

:warning: NOTICE the trailing . after `cm.gelighting.com.` in `local-data:`. :warning:

```
server:
access-control-view: 10.0.1.167/32 cync-override

view:
name: "cync-override"
local-zone: "homelab" static
local-data: "cm.gelighting.com. 90 IN A 10.0.1.9"
```



## Launching the server

I found it easiest to first start the server, then turn on/plug in/power cycle the devices.

:warning: **Devices need to be power cycled before they will connect to the LAN server**

Devices that are powered on and currently talking to the Cync cloud will need to be power cycled. 

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

# Power cycle devices after starting server
The devices make the DNS query on first startup - you need to cycle power for all devices on the network for them to use your local server.
