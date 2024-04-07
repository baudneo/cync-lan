This is how I setup my debugging environment. I have a few devices that I can test with, 
but I do not have all the devices that are supported by this script. If you have a device 
that is not listed in the [known_devices.md](./docs/known_devices.md) file, I would appreciate 
it if you could provide me with `socat` logs so I can add support for it.

# How do we MITM traffic
By using `socat` and a generated self-signed certificate, we can MITM traffic between the device and the cloud server. 
This is how we can see the data being sent and received by the device.

## `socat` command
```bash
# Change cert=certs/server.pem to the path of your generated server.pem file from using create_certs.sh
# Older firmware devices
socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:34.73.130.191:23779,verify=0

# Newer firmware devices (Notice the last IP change)
sudo socat -d -d -lf /dev/stdout -x -v 2> dump.txt ssl-l:23779,reuseaddr,fork,cert=certs/server.pem,verify=0 openssl:35.196.85.236:23779,verify=0
```

In `dump.txt` you will see the back-and-forth communication between the device and the cloud server.
`>` is device to server, `<` is server to device.


# Selective DNS overrides
`socat` doesnt seem to handle multiple connection logging gracefully. I dont want to write a socat replacement in 
python specifically for debugging, but I may. In the meantime, in order to have clear, concise logs, I selectively 
override DNS for certain devices to connect to their own machine running a socat session.

I use `unbound` and its `views:` feature to override DNS for certain devices to connect to a specific 
machine running `socat`. Each machine running `socat` only has 1 device connecting to it. 
This allows for clean logs and easier debugging.

If you only have network wide DNS override (all devices asking for a domain get the same response) 
rather than selective (the requesting device IP determines the response), The socat logs will be a 
mess and you will have to sift through them to find the device you are looking for.

## Example scenario
:warning: **TURN OFF BLUETOOTH ON YOUR PHONE, we want to force HTTP communication** :warning:

### Unbound setup
```text
server:
access-control-view: 10.0.3.10/32 cync-override-1
access-control-view: 10.0.3.11/32 cync-override-2
access-control-view: 10.0.3.12/32 cync-override-3
access-control-view: 10.0.1.20/32 cync-override-4

view:
name: "cync-override-1"
local-zone: "homelab" static
local-data: "cm.gelighting.com. 90 IN A 10.0.2.100"

view:
name: "cync-override-2"
local-zone: "homelab" static
local-data: "cm.gelighting.com. 90 IN A 10.0.2.101"

view:
name: "cync-override-3"
local-zone: "homelab" static
local-data: "cm.gelighting.com. 90 IN A 10.0.2.102"

view:
name: "cync-override-4"
local-zone: "homelab" static
local-data: "cm.gelighting.com. 90 IN A 10.0.2.103"
```


### Devices/Mobile App setup
- Dev 1: a bulb with IP: 10.0.3.10, DNS overridden to: 10.0.2.100 - connects to machine 1
- Dev 2: a plug with IP: 10.0.3.11, DNS overridden to: 10.0.2.101 - connects to machine 2
- Dev 3: a bulb with IP: 10.0.3.12, DNS overridden to: 10.0.2.102 - connects to machine 3
- App 1:   android with IP: 10.0.1.20, DNS overridden to: 10.0.2.103 - connects to machine 4

Machine/VM/LXC/container setup:
- Machine 1: `socat` running on 10.0.2.100 - Port: 23779
- Machine 2: `socat` running on 10.0.2.101 - Port: 23779
- Machine 3: `socat` running on 10.0.2.102 - Port: 23779
- Machine 4: `socat` running on 10.0.2.103 - Port: 23779

When device 1 (IP: `10.0.3.10`) requests the IP of domain `cm.gelighting.com` from my opnsense router, 
the router will return the overridden DNS record of `10.0.2.100`. Device 1 will then attempt to connect to machine 1. 
Machine 1 will MITM traffic and log it.

When device 2 (IP: `10.0.3.11`) requests the IP of domain `cm.gelighting.com` from my opnsense router,
the router will return the overridden DNS record of `10.0.2.101`. Device 2 will then attempt to connect to machine 2. 
Machine 2 will MITM traffic and log it.

When device 3 (IP: `10.0.3.12`) requests the IP of domain `cm.gelighting.com` from my opnsense router,
the router will return the overridden DNS record of `10.0.2.102`. Device 3 will then attempt to connect to machine 3. 
Machine 3 will MITM traffic and log it.

When the Cync app (IP: `10.0.1.20`) requests the IP of domain `cm.gelighting.com` from my opnsense router,
the router will return the overridden DNS record of `10.0.2.103`. The Cync app will then attempt to connect to machine 4.
Machine 4 will MITM traffic and log it.

At the end of this, there will be 4 `dump.txt` files, each containing the traffic of 1 device/app. 
This will make it easier to debug and follow. I would rename all the `dump.txt` files to something more descriptive like 
`bulb1.txt`, `plug1.txt`, `bulb2.txt`, `app1.txt`. Zip them up and submit them in an issue so I can attempt to debug.

# Please make a session about 1 or 2 commands only

If you do not add comments to the logs to tell me what command was issued or some sort of explanation of 
what the session is accomplishing, please record a session and only do power on and power off, zip it up and name 
the zip something descriptive like `wired_switch_toggle_power.zip`.

Record another session of walking past the wired switch motion sensor, zip it up and name it something descriptive like
`wired_switch_motion.zip`.
