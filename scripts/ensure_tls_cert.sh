#!/bin/sh
set -eu

cert_dir=/etc/alderpointdns/certs
cert_file="$cert_dir/alderpointdns-lab.crt"
key_file="$cert_dir/alderpointdns-lab.key"

if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
  exit 0
fi

if [ -e "$cert_file" ] || [ -e "$key_file" ]; then
  echo "Refusing to overwrite partial TLS material in $cert_dir" >&2
  exit 1
fi

install -d -m 0750 -o root -g _dnsdist "$cert_dir"
openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -subj "/CN=alderpointdns.local" \
  -addext "subjectAltName=DNS:alderpointdns.local,IP:127.0.0.1" \
  -keyout "$key_file" \
  -out "$cert_file"
chown root:_dnsdist "$cert_file" "$key_file"
chmod 0644 "$cert_file"
chmod 0640 "$key_file"
