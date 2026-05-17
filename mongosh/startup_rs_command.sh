bash
-c
echo '127.0.0.1 mmjprod-mongo-dzvg0s' >> /etc/hosts && echo 'a3f8c2d1e4b7f9a2c5d8e1b4f7a0c3d6hju2f5a8c1d4e7b0f3a6c9d2e5b8f1a4' > /etc/mongo-keyfile && chmod 400 /etc/mongo-keyfile && chown 999:999 /etc/mongo-keyfile && docker-entrypoint.sh mongod --replSet rs0 --bind_ip_all --keyFile /etc/mongo-keyfile
