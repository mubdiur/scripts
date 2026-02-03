## Add the following to the "Custom docker options"

```bash
/bin/bash -c "openssl rand -base64 756 > /data/replica.key && chmod 400 /data/replica.key && chown mongodb:mongodb /data/replica.key && docker-entrypoint.sh mongod --replSet rs0 --keyFile /data/replica.key --bind_ip_all"
```
