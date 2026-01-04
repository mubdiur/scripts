#!/bin/bash

# Usage: ./setup_primary.sh <MONGO_URI> <EXTERNAL_HOSTNAME>
# Example: ./setup_primary.sh "mongodb://user:pass@localhost:27017" "codealign-mongo-zleqar"

# 1. Check arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <connection_uri> <external_host>"
    echo "Example: $0 \"mongodb://root:secret@localhost:27017\" \"mongo.example.com\""
    exit 1
fi

MONGO_URI="$1"
EXTERNAL_HOST="$2"

echo "----------------------------------------------------"
echo "MongoDB Auto-Configure Script"
echo "Target: $MONGO_URI"
echo "New Host: $EXTERNAL_HOST"
echo "----------------------------------------------------"

# 2. Construct the Javascript to run inside Mongo
# This script does three things:
# A. Updates the hostname in the config.
# B. Sets priority to 100 (so it wins elections instantly).
# C. Sets catchUpTimeout to -1 (no waiting).
# D. Uses {force: true} to push changes even if the cluster is grumpy.

MONGOSH_SCRIPT="
var conf = rs.conf();
var host = '$EXTERNAL_HOST:27017';

// 1. Check if we need to change the host
if (conf.members[0].host !== host) {
    print('Updating host from ' + conf.members[0].host + ' to ' + host);
    conf.members[0].host = host;
} else {
    print('Host is already correct: ' + host);
}

// 2. Force Primary settings
conf.members[0].priority = 100;
conf.settings.catchUpTimeoutMillis = -1;

// 3. Apply Config
print('Forcing configuration reconfig...');
rs.reconfig(conf, {force: true});
print('SUCCESS: Node is now configured as Primary.');
"

# 3. Execute using mongosh
# We connect to the 'admin' database directly to ensure auth works.
# We use --eval to run the script.

mongosh "$MONGO_URI/admin?authSource=admin" --eval "$MONGOSH_SCRIPT"

echo "----------------------------------------------------"
echo "Done. Please wait 5 seconds for the node to stabilize."
echo "----------------------------------------------------"
echo "Example connection string: mongosh \"mongodb://mongo:yiflzrcheyzxp9m5@codealign-mongo-zleqar:27017/codealign-main?replicaSet=rs0&authSource=admin&w=1\""