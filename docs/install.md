# Install

This VM is installed from Debian packages plus the official PowerDNS dnsdist
repository. The PowerDNS package is required for DNS-over-QUIC support.

Core packages:

```sh
apt-get install -y bind9 bind9-dnsutils knot-dnsutils curl openssl jq sudo
apt-get install -y python3-fastapi uvicorn python3-uvicorn python3-jinja2 python3-argon2 python3-itsdangerous python3-multipart python3-yaml
```

PowerDNS dnsdist package on Debian 13:

```sh
install -d /etc/apt/keyrings
curl https://repo.powerdns.com/FD380FBB-pub.asc > /etc/apt/keyrings/dnsdist-21-pub.asc
cat >/etc/apt/sources.list.d/pdns.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/dnsdist-21-pub.asc] http://repo.powerdns.com/debian trixie-dnsdist-21 main
EOF
cat >/etc/apt/preferences.d/dnsdist-21 <<'EOF'
Package: dnsdist*
Pin: origin repo.powerdns.com
Pin-Priority: 600
EOF
apt-get update
apt-get install -y dnsdist
dnsdist --version | grep dns-over-quic
```

TLS bootstrap:

```sh
/opt/bindguard/scripts/ensure_tls_cert.sh
```

Services:

```sh
systemctl enable --now named
systemctl enable --now dnsdist
systemctl enable --now bindguard
```

Lab web interface:

```sh
curl http://<vm-lan-ip>:3000/setup
```

No default administrator exists. Create the first administrator through
`/setup`.
