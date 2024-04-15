# devices never connect / devices stay unavailable / offline
If you followed the [DNS docs](./DNS.md) and the [Install docs](./INSTALL.md) and devices are still not connecting, 
you may need to check your network configuration (firewall, etc.). If the Cync devices are on a separate subnet, 
make sure that all Cync devices can talk to the local IP of the machine running `cync-lan`.

## Example

### OPNSense
![OPNSense Firewall Rules Example](./assets/opnsense_firewall_rules_example.png)
