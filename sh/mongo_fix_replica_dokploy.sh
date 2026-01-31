#!/bin/bash
# MongoDB Replica Set Configuration Updater
# Usage: ./script.sh
#   - Prompts for connection string (format: mongodb://username:password@host:port)
#   - Connects via localhost (for container/SSH environments)
#   - Updates all replica set members to use the new hostname
# After running: append ?replicaSet=rs0&authSource=admin to your connection string

# Prompt for connection string
read -p "Enter MongoDB connection string (e.g., mongodb://user:pass@host:27017): " CONNECTION_STRING

# Validate that input is not empty
if [ -z "$CONNECTION_STRING" ]; then
  echo "Error: Connection string cannot be empty."
  exit 1
fi

# Validate connection string format (basic check for mongodb:// prefix)
if [[ ! "$CONNECTION_STRING" =~ ^mongodb:// ]]; then
  echo "Error: Connection string must start with 'mongodb://'"
  echo "Example: mongodb://username:password@host:port"
  exit 1
fi

# Validate that connection string contains @ (username:password@host format)
if [[ ! "$CONNECTION_STRING" =~ @ ]]; then
  echo "Error: Connection string must include credentials in format: mongodb://username:password@host"
  exit 1
fi

echo ""
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

    // --- Update ALL Replica Set Members ---
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
