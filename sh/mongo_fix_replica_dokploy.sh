#!/bin/bash
# After running this script, use <mongourl/dbname>?replicaSet=rs0&authSource=admin
# bash <(curl -fsSL https://raw.githubusercontent.com/mubdiur/scripts/refs/heads/main/sh/mongo_fix_replica_dokploy.sh) "mongodb://mongo:iulu3mhzi26nbpa8@sentora-db-ne2cgq:27017"
# mongosh "/?replicaSet=rs0&authSource=admin"
# Check if an argument is provided
if [ -z "$1" ]; then
  echo "Usage: ./update_rs.sh <connection_string>"
  echo "Example: ./update_rs.sh mongodb://user:pass:27017/orifine-main?replicaSet=rs0&authSource=admin"
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

echo "Parsed user: $USERNAME"
echo "Parsed target host: $TARGET_HOST"

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
    var targetHost = '$TARGET_HOST';
    print('Target Host set to: ' + targetHost);

    // --- STEP 1: Try to allow listening on all hosts (0.0.0.0) ---
    // Note: This attempts a runtime update. If it fails, you must set 
    // 'net.bindIp: 0.0.0.0' in mongod.conf and restart the service.
    try {
        var res = db.adminCommand({ setParameter: 1, bindIp: '0.0.0.0' });
        if (res.ok === 1) {
            print('Success: Server set to listen on 0.0.0.0 (all interfaces).');
        } else {
            print('Warning: Could not update bindIp dynamically.');
            print('Please ensure bindIp is set to 0.0.0.0 in your configuration file.');
        }
    } catch (e) {
        print('Info: Could not set bindIp dynamically (permission or version restriction).');
    }

    print('---');

    // --- STEP 2: Update ALL Replica Set Members ---
    try {
        var cfg = rs.conf();
        
        if (!cfg) {
            throw 'This instance is not part of a Replica Set.';
        }

        var count = cfg.members.length;
        print('Found ' + count + ' member(s) in the replica set configuration.');
        print('Updating all members to point to: ' + targetHost + ' ...');

        // Loop through ALL members (not just index 0)
        for (var i = 0; i < count; i++) {
            var oldHost = cfg.members[i].host;
            cfg.members[i].host = targetHost;
            print('  [' + i + '] ' + oldHost + ' -> ' + targetHost);
        }
       
        // Force reconfiguration is required when changing hostnames
        var result = rs.reconfig(cfg, { force: true });
       
        print('-----------------------------------');
        print('Success! RS Config updated.');
        print('You can now connect using the host: ' + targetHost);
    } catch (e) {
        print('Error updating config:');
        print(e);
    }
"

echo "--- Done ---"
