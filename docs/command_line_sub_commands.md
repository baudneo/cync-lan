There are a few different CLI args that cync-lan supports.

# Run
Parse the config file, connect to MQTT broker and start the TCP server.

## Required Arguments
- Config file path: path to exported file.
    - `cync-lan.py run /path/to/cync_mesh.yaml`

## Optional Arguments
- `--debug` - enable debug logging

# Export
Export a cync-lan YAML config file from the Cync cloud API. 
If no credentials are supplied via flags, the user will be prompted for them.

**Also creates a `./raw_mesh.yaml` YAML file which has all exported data from the cloud for the curious**

## Required Arguments
- Output file path: path to export file.
    - `cync-lan.py export ./cync_mesh.yaml`

## Optional Arguments
- `--email|-e`: email address for the Cync account.
- `--password|-p`: password for the Cync account.
- `--code|--otp|-c|-o`: code sent to the email address during the export process.
- `--save-auth|-s`: save the auth token data to a file for future use.
- `--auth-output|-a`: path to save the auth token data to file.
- `--auth`: path to a file containing the auth token data (saves from entering credentials each export).
