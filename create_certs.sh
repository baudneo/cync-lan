#!/bin/bash -e

mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -subj '/CN=cm.gelighting.com' -sha256 -days 3650 -nodes
cat certs/key.pem certs/cert.pem > certs/server.pem