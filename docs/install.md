# Install

This VM is already installed from local Debian packages.

Core packages:

```sh
apt-get install -y bind9 bind9-dnsutils dnsdist knot-dnsutils curl openssl jq sudo
apt-get install -y python3-fastapi uvicorn python3-uvicorn python3-jinja2 python3-argon2 python3-itsdangerous python3-multipart python3-yaml
```

Services:

```sh
systemctl enable --now named
systemctl enable --now dnsdist
systemctl enable --now bindguard
```

Lab web interface:

```sh
curl http://127.0.0.1:3000/setup
```

No default administrator exists. Create the first administrator through
`/setup`.
