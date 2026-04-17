# Add-ons

## Installation

Adding this add-ons repository to your Home Assistant instance is
pretty straightforward. In the Home Assistant add-on store,
a possibility to add a repository is provided.

Use the following URL to add this repository:

```txt
https://github.com/baudneo/cync-lan
```

[![Add Repository to HA][my-ha-badge]][my-ha-url]

## Export Cync Mesh

Install the cync-lan export add-on and fill out the configure page with cync username (email) and password. Then start the add-on, copy the OTP from the provided email, open the web-ui from the export add-on, and run the export action.

After the export is complete, the add-on can be stopped/uninstalled. This add-on only needs to be ran if new devices are added.

## Configure MQTT and DNS

Install a MQTT add-on; the default Mosquitto broker add-on will work. After one is installed, install a DNS server; Dnsmasq will work. Configure cm.gelighting.com and/or cm-ge.xlink.cn to point to the IP of local Home Assistant.

Dnsmasq Example:

```txt
- host: cm.gelighting.com
  ip: 192.168.1.5
- host: cm-ge.xlink.cn
  ip: 192.168.1.5
```

Point the DNS of cync devices to use Home Assistant as the DNS provider (probably will need to update WiFi DHCP settings).

## Install cync-lan

Install and start the cync-lan add-on. It may take a minute or two, but devices should start showing up in Home Assistant.

[my-ha-badge]: https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg
[my-ha-url]: https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fbaudneo%2Fcync-lan
