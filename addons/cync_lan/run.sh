#!/usr/bin/with-contenv bashio

# Confirm MQTT service is available and map config
if bashio::services.available mqtt ; then
  export CYNC_MQTT_HOST="$(bashio::services mqtt 'host')"
  export CYNC_MQTT_PORT="$(bashio::services mqtt 'port')"
  export CYNC_MQTT_USER="$(bashio::services mqtt 'username')"
  export CYNC_MQTT_PASS="$(bashio::services mqtt 'password')"
fi

# Map email and username config
export CYNC_ACCOUNT_USERNAME=$(bashio::config 'email')
export CYNC_ACCOUNT_PASSWORD=$(bashio::config 'password')

# Start Server
cync-lan
tail -f /dev/null