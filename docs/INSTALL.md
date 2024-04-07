# Installation

:warning: **Either way you run this, you will need to setup the virtualenv in order to 
export devices from the Cync cloud to a YAML file** :warning:

You can run this in a docker container or in a virtual environment on your system.

## virtualenv
**This is required in order to at least export devices from the Cync cloud to a YAML file.**

System packages you will need (package names are from a debian based system):
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

# create self-signed key/cert pair, wget the bash script and execute
wget https://raw.githubusercontent.com/baudneo/cync-lan/python/create_certs.sh
bash ./create_certs.sh

# install python deps
pip install pyyaml requests uvloop wheel
pip install git+https://github.com/Yakifo/amqtt.git

# wget file
wget https://raw.githubusercontent.com/baudneo/cync-lan/python/src/cync-lan.py

# Run script to export cloud device config to ./cync_mesh.yaml
# It will ask you for email, password and the OTP emailed to you.
# --save-auth flag will save the auth data to its own file (./auth.yaml)
# You can supply the auth file in future export commands using -> export ./cync_mesh.yaml --auth ./auth.yaml
python3 ~/cync-lan/cync-lan.py export ~/cync-lan/cync_mesh.yaml --save-auth
```

### Run the script
```bash
#make sure virtualenv is activated

source ~/cync-lan/venv/bin/activate
# Run the script to start the server, provide the path to the config file
# You can add --debug to enable debug logging
python3 ~/cync-lan/cync-lan.py run ~/cync-lan/cync_mesh.yaml
```

## Docker

First, you **MUST** follow the virtualenv installation to generate certs and export devices from the Cync cloud.

- Create a dir for your docker setup. i.e. `mkdir -p ~/docker/cync-lan/config`
- Copy the exported config file from the [virtualenv install](#virtualenv): `cp ~/cync-lan/cync_mesh.yaml ~/docker/cync-lan/config` 
- Download the example docker-compose file: `cd ~/docker/cync-lan && wget https://raw.githubusercontent.com/baudneo/cync-lan/python/docker-compose.yaml`
- Edit `docker-compose.yaml` and change `MQTT_URL` env var to match your MQTT broker details (can also enable DEBUG logs)
- Run `docker compose up -d --force-recreate` to bring the container up
- Optional: check logs using `docker compose logs -f` (Ctrl+C to exit)

### Supported architectures
- `linux/amd64`
- `linux/arm64`
- `linux/armv7`

### Build image yourself
```bash
docker build -t cync-lan:custom-tag .
```