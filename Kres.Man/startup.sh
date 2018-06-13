#!/bin/bash
cd /app
#dump variables to files
echo $CA_CRT_BASE64 | base64 -d > cacert.pem
echo $CLIENT_CRT_BASE64 | base64 -d > cert.pem
echo $CLIENT_KEY_BASE64 | base64 -d > key.pem

#convert to pfx
openssl pkcs12 -export -nodes -out /app/client.pfx -inkey key.pem -in cert.pem -certfile cacert.pem -passout pass:WhateverYouWish
export RESOLVER_ID=$(openssl x509 -noout -subject -in ./cert.pem  | sed -e "s/^subject= //" | sed -ne 's/.*CN\s*=\s*\(\d*\)/\1/p')
echo "Resolver ID is $RESOLVER_ID"

#remove temp files (leave just pfx)
rm cacert.pem cert.pem key.pem
dotnet run

