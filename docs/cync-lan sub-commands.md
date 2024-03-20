There are a few different CLI commands that cync-lan supports.

# Run
Parse the config file, connect to MQTT broker and start the TCP server.

## Required Arguments
- Config file path: path to exported file.
    - `cync-lan.py run cync_mesh.yaml`

## Optional Arguments
- `--debug` - enable debug logging
- `--env|-e` - specify a .env file to load environment variables from

# Export
Export a cync-lan YAML config file from the Cync cloud API. 
If no credentials are supplied via flags, the user will be prompted for them.

**Also creates a `./raw_mesh.yaml` file which has all exported data from the cloud for the curious**

## Required Arguments
- Output file path: path to export file.
    - `cync-lan.py export ./cync_mesh.yaml`

## Optional Arguments
- `--email|-e`: email address for the Cync account.
- `--password|-p`: password for the Cync account.
- `--code|--otp|-c|-o`: code sent to the email address.
- `--save-auth|-s`: save the auth token data to a file for future use.
- `--auth|-a`: path to a file containing the auth token data.

# Certs
Generate a self-signed certificate for use with the server. 

## Required Arguments
- Common Name: the CN field of the certificate. Set to `*.xlink.cn` by default so not really required.
    - `cync-lan.py certs` - `*.xlink.cn` is set by default.
    - `cync-lan.py certs some.server.tld`

## Optional Arguments
- `--output_dir|-o`: directory to save the certificate and key to. Defaults to `./certs`.

