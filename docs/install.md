# Install

Alderpoint DNS is currently beta software (v0.4.0-beta.2); see
`docs/known-limitations.md` and `docs/beta-readiness.md` before deploying it
anywhere you rely on. Alderpoint DNS supports installation from a reviewed
local source tree on a fresh Debian-based server. Do not pipe an unreviewed
remote script directly into a root shell; download a release artifact,
verify its checksum/signature when published, inspect `scripts/install.sh`,
then run it locally.

Supported operating systems for this installer:

- Debian 12 and Debian 13
- Ubuntu 24.04 LTS and 26.04 LTS, using Debian-compatible package names where
  available

Minimum resources:

- 64-bit x86_64/amd64 or arm64/aarch64
- 512 MiB RAM minimum; 1 GiB or more recommended
- 1 GiB free disk minimum for installation; 4 GiB or more recommended for
  backups, logs, analytics, and generated DNS data

The installer creates this layout:

- Application code: `/opt/alderpointdns`
- Configuration and secrets: `/etc/alderpointdns`
- Persistent database/generated DNS/backups/import staging:
  `/var/lib/alderpointdns`
- Logs: `/var/log/alderpointdns`
- Systemd units: `/etc/systemd/system`

Run:

```sh
cd /path/to/alderpointdns-release
sudo ./scripts/install.sh
```

For isolated validation without changing the host:

```sh
ALDERPOINTDNS_INSTALL_ROOT=/tmp/alderpointdns-install-root ./scripts/install.sh --dry-run --skip-apt
```

Alderpoint DNS installs from Debian's normal package repositories, with no
third-party repository required. It depends on `dnsdist (>= 1.9.0)`, which
Debian 13 ("trixie") ships in its own archive (`dnsdist 1.9.x`); `apt-get
install -y ./alderpointdns_<version>_all.deb` (or `scripts/install.sh`)
resolves and installs it automatically like any other dependency.

Core packages (the `.deb`'s own `Depends:` installs these automatically;
listed here for a manual/from-source install):

```sh
apt-get install -y bind9 bind9-dnsutils knot-dnsutils curl openssl jq sudo dnsdist
apt-get install -y python3-fastapi uvicorn python3-uvicorn python3-jinja2 python3-argon2 python3-itsdangerous python3-multipart python3-yaml
apt-get install -y python3-dnspython python3-httpx python3-aioquic
apt-get install -y python3-openpyxl
```

`python3-dnspython`/`python3-httpx`/`python3-aioquic` provide real DoH/DoH3/DoQ
functional query testing for Encryption Settings deployments
(`app/encryption.py`); `knot-dnsutils` (`kdig`) provides the DoT test.
`python3-openpyxl` provides XLSX parsing for Import and Migration
(`app/importer.py`); `python3-yaml` (already listed above) parses AdGuard
Home's `AdGuardHome.yaml`.

Debian's own dnsdist package supports plain DNS, DoH, DoT, DNSCrypt, and
everything Alderpoint DNS's BIND backend integration needs (packet cache,
ACLs, analytics logging, authenticated local web/API access). It does not
include DNS-over-QUIC (DoQ) or DNS-over-HTTP/3 (DoH3) — see
`docs/dnsdist.md` for how Alderpoint DNS detects this and keeps those two
transports off (and clearly marked unsupported in Encryption Settings)
rather than trying to start a listener the binary can't provide.

DoQ/DoH3 are optional. If you specifically need them, install dnsdist from
the official PowerDNS repository *before* installing the Alderpoint DNS
package, and Alderpoint DNS will detect and use the extra capability
automatically:

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
/opt/alderpointdns/scripts/ensure_tls_cert.sh
```

Services:

```sh
systemctl enable --now named
systemctl enable --now dnsdist
systemctl enable --now alderpointdns
```

Lab web interface:

```sh
curl http://<vm-lan-ip>:3000/setup
```

No default administrator exists. Create the first administrator through
`/setup`.

The installer performs OS/resource checks, installs packages, creates the
`alderpointdns` system user/group, creates a Python virtual environment with
system package access, generates local secrets, initializes the database,
deploys generated DNS configuration, enables services, and runs final health
checks. It refuses to overwrite an existing `/opt/alderpointdns` installation; use
`scripts/upgrade.sh` for upgrades.
