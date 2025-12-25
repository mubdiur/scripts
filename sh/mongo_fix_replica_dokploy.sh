#!/bin/bash

# After running this script, use <mongourl/dbname>?replicaSet=rs0&authSource=admin
# Check if an argument is provided
if [ -z "$1" ]; then
  echo "Usage: ./update_rs.sh <connection_string>"
  echo "Example: ./update_rs.sh mongodb://user:pass@host:27017"
  exit 1
fi

CONNECTION_STRING="$1"

echo "--- MongoDB Replica Set Config Updater ---"

# 1. Parse the Connection String
# Remove protocol prefix (mongodb://)
TEMP_STR="${CONNECTION_STRING#*://}"

# Extract Credentials (everything before the last @)
CREDS="${TEMP_STR%@*}"
USERNAME="${CREDS%:*}"
PASSWORD="${CREDS#*:}"

# Extract Hostname and Port (everything after the last @)
# We also strip any trailing slash or database name if present
HOST_PORT_RAW="${TEMP_STR##*@}"
TARGET_HOST="${HOST_PORT_RAW%%/*}"

echo "parsed user: $USERNAME"
echo "parsed target host: $TARGET_HOST"

# 2. Detect Mongo Client (mongosh or mongo)
if command -v mongosh &> /dev/null; then
    MONGO_CMD="mongosh"
elif command -v mongo &> /dev/null; then
    MONGO_CMD="mongo"
else
    echo "Error: Neither 'mongosh' nor 'mongo' command found."
    exit 1
fi

echo "Using command: $MONGO_CMD"

# 3. Connect via Localhost and Update Configuration
# We connect to 127.0.0.1 inside the container to ensure we can reach the service
# regardless of what the current RS config thinks the hostname is.

$MONGO_CMD "mongodb://127.0.0.1:27017" \
  --username "$USERNAME" \
  --password "$PASSWORD" \
  --authenticationDatabase admin \
  --eval "
    try {
        var cfg = rs.conf();
        print('Current Host: ' + cfg.members[0].host);
        
        // Update the host of the first member (index 0)
        cfg.members[0].host = '$TARGET_HOST';
        
        // Force reconfiguration is usually required when changing the hostname of the primary
        // or if the set is currently considered 'unhealthy' due to hostname mismatch.
        var result = rs.reconfig(cfg, { force: true });
        
        print('-----------------------------------');
        print('Success! RS Config updated to: $TARGET_HOST');
        print(JSON.stringify(result));
    } catch (e) {
        print('Error updating config:');
        print(e);
    }
"

echo "--- Done ---"
