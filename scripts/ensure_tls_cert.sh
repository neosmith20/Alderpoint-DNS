#!/bin/sh
set -eu

cert_dir=/etc/alderpointdns/certs
cert_file="$cert_dir/alderpointdns-lab.crt"
key_file="$cert_dir/alderpointdns-lab.key"

# 0751, not 0750: root/_dnsdist keep read+execute (so dnsdist can list and
# read its own cert/key material, and only root can write into the
# directory), but "other" needs the execute (search/traversal) bit too --
# without it, the unprivileged alderpointdns web process (in neither root
# nor _dnsdist) gets EPERM on a bare stat() of alderpointdns-lab.crt, even
# though the certificate file itself is world-readable (0644) and only the
# private key (0640, root:_dnsdist, correctly unreadable by "other") is
# meant to be withheld from it. Run this unconditionally, even when cert
# material already exists, so upgrading an install that predates this fix
# also picks up the corrected mode instead of only fresh installs.
install -d -m 0751 -o root -g _dnsdist "$cert_dir"

if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
  exit 0
fi

if [ -e "$cert_file" ] || [ -e "$key_file" ]; then
  echo "Refusing to overwrite partial TLS material in $cert_dir" >&2
  exit 1
fi

openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -subj "/CN=alderpointdns.local" \
  -addext "subjectAltName=DNS:alderpointdns.local,IP:127.0.0.1" \
  -keyout "$key_file" \
  -out "$cert_file"
chown root:_dnsdist "$cert_file" "$key_file"
chmod 0644 "$cert_file"
chmod 0640 "$key_file"
