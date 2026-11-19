#!/usr/bin/env bash
# Example PKI for trying the module: a CA and one device certificate.
# Everything goes to pki/ (git-ignored). Not for production as-is.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p pki && cd pki
umask 077
DEVICE=${1:-phone}

if [ ! -f ca.key ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/O=Example/CN=Example mTLS CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt
fi

openssl ecparam -name prime256v1 -genkey -noout -out "$DEVICE.key"
openssl req -new -key "$DEVICE.key" -subj "/O=Example/CN=$DEVICE" -out "$DEVICE.csr"
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n" > client.ext
openssl x509 -req -in "$DEVICE.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile client.ext -out "$DEVICE.crt"

# PKCS#12 for Android's KeyChain. Legacy algorithms parse on every Android version; the empty
# password means the system installer does not ask for one (delete the file after installing).
openssl pkcs12 -export -inkey "$DEVICE.key" -in "$DEVICE.crt" -certfile ca.crt -name "mtls-$DEVICE" \
  -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 -passout pass: -out "$DEVICE.p12"

echo "CA:     pki/ca.crt  (give to nginx as ssl_client_certificate)"
echo "Device: pki/$DEVICE.p12 (install on the phone as alias mtls-$DEVICE)"
