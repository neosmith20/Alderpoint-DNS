# dnsdist frontend

Alderpoint DNS uses dnsdist as the only client-facing DNS frontend.

Current lab configuration:

- Plain UDP/TCP DNS: `0.0.0.0:53`, `[::]:53`
- DoH: `https://<vm-lan-ip>/dns-query`
- DoH3: UDP `0.0.0.0:443`, `[::]:443` (only if the installed dnsdist build supports it)
- DoT: `0.0.0.0:853`, `[::]:853`
- DoQ: UDP `0.0.0.0:853`, `[::]:853` (only if the installed dnsdist build supports it)
- BIND backend: `127.0.0.1:5354` with PROXYv2 client address forwarding
- BIND recovery/health listener: `127.0.0.1:5353`
- ACL: RFC1918 private networks, loopback, and `fc00::/7` by default
- dnsdist web/API: `127.0.0.1:8083`, random local credentials
- dnsdist console: `127.0.0.1:5199`, random local key

Set `ALDERPOINTDNS_DNS_ALLOW_ALL=1` in the dnsdist service environment to allow
queries from all IPv4 and IPv6 clients. Alderpoint DNS expects your network firewall (VLAN/segmentation rules) to
be the network exposure boundary.

Encryption Settings writes `ALDERPOINTDNS_DNS_LISTEN_IPV4` and
`ALDERPOINTDNS_DNS_LISTEN_IPV6` into the dnsdist systemd override. The defaults
are `0.0.0.0` and `::`; blanking either family disables listeners for that
family, and at least one family must remain configured.

### dnsdist build and capability detection

Alderpoint DNS depends on `dnsdist (>= 1.9.0)` and installs cleanly from
Debian 13's own archive (`dnsdist 1.9.x`) with no third-party repository —
this is the default, tested install path. That build supports plain DNS,
DoH, DoT, DNSCrypt, and everything the BIND backend integration needs
(packet cache, ACLs, remote-logging analytics, authenticated local
web/API access), but does not include DNS-over-QUIC or DNS-over-HTTP/3
(`dnsdist --version` will not list `dns-over-quic` or `dns-over-http3`
among its "Enabled features").

`app/encryption.py`'s `dnsdist_capabilities()` detects this directly by
parsing `dnsdist --version`'s feature list at deploy time (and again live
in the web UI, via `/encryption`). DoQ and DoH3 are:

- **off by default** (`packaging/dnsdist.service.d/alderpointdns.conf`
  ships `ALDERPOINTDNS_DNS_DOQ=0`/`ALDERPOINTDNS_DNS_DOH3=0`), so a fresh
  install never attempts to start a listener the installed build can't
  provide;
- **shown as unsupported, not enabled or broken**, in Encryption
  Settings — their checkboxes render disabled with an explanatory badge
  when the installed dnsdist lacks the capability;
- **defensively re-checked at deploy time** in `deploy_encryption()`: even
  if a saved configuration requests DoQ/DoH3 (for example, restored from a
  backup taken on a QUIC-capable install), the deploy step disables just
  that protocol and reports why in the deployment message, rather than
  restarting dnsdist into a failed protocol test that would roll back
  every other protocol along with it.

`packaging/dnsdist.conf` itself also wraps every DoQ/DoH3/DNSCrypt
`add*Local`/`add*Bind` call in `alderpointdnsSafeCapabilityCall()`, which
checks the Lua function exists and `pcall`s it, so even a hand-edited or
manually deployed configuration degrades safely instead of crash-looping
dnsdist.

DoQ/DoH3 are optional. To use them, install dnsdist from the official
PowerDNS `trixie-dnsdist-21` repository — either before installing
Alderpoint DNS (see `docs/install.md`) or after, with:

```sh
sudo alderpointdns install-enhanced-dnsdist
```

and verify `dnsdist --version` reports `dns-over-quic`; Alderpoint DNS then
detects and exposes the extra capability automatically, with no reinstall
required.

Validation commands:

```sh
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
systemctl status dnsdist --no-pager
/opt/alderpointdns/tests/test_dnsdist_frontend.sh
```

### Runtime status model (Encryption Settings / `/dns-settings`)

Each protocol's row in the Protocol Status table (`app/webapp.py`'s
`protocol_statuses()`) is derived from three independent, authoritative
checks — never from grepping a generated config file for a variable name,
and never from a TCP/UDP-address-only socket check:

1. **Build support** — is the transport in the *installed* dnsdist's
   `Enabled features` list (`app/encryption.py`'s `dnsdist_capabilities()`)?
2. **Runtime status** — is Alderpoint's own setting for the protocol on
   (`encryption_settings` in the database, the same source `deploy_encryption()`
   reads), and is the exact expected `(transport, address:port)` socket
   present, per `ss -H -ltnup`? TCP and UDP are checked separately —
   dnsdist's TCP DoH listener on `443` and TCP DoT listener on `853` can
   never satisfy DoH3's UDP-443 or DoQ's UDP-853 check, since they share
   only the port number, not the transport.
3. **Verification** — was there an actual recorded live query for that
   protocol from the most recent deployment (`encryption.test_protocols()`),
   or only a configuration check?

| State | Meaning |
| --- | --- |
| Unavailable | installed dnsdist build lacks the capability |
| Disabled | build supports it, Alderpoint's setting is off |
| Configured but not listening | setting is on and deployed, but the expected socket is absent |
| Listening | setting is on and the correct TCP/UDP socket exists |
| Degraded | runtime state and configured state disagree (e.g. only one address family up, or a socket exists despite the setting being off) |

"Live query verified" is only shown when `deploy_encryption()`'s
`test_protocols()` actually recorded a successful end-to-end query over that
protocol using a capability-aware test client (see below) — never merely
because `dnsdist --check-config` passed or a unit test exercised the
detection logic. A DoQ/DoH3 query is only attempted when a known-capable
test client is installed (`python3-dnspython`/`python3-aioquic`); on a build
or environment without one, the result is reported as configuration-checked
or socket-verified, distinctly from an end-to-end verified query.

### Managed-block migrations for existing installs

`ensure_dnsdist_conf_parameterized()` (`app/encryption.py`) only ever
re-templates `/etc/dnsdist/dnsdist.conf` once per install -- after that it's
a permanent no-op, by design, so it never discards anything an administrator
hand-edits into the file. That means a later template change (like the
Alt-Svc header) doesn't reach an already-migrated install on its own.

Instead, each such change ships its own narrowly-scoped, marker-delimited
migration -- `ensure_doh_altsvc_migration()` for the Alt-Svc header is the
first one. It runs on every `deploy_encryption()` call (so every upgrade and
every Encryption Settings save), and:

- is a no-op if the file already contains its `-- ALDERPOINT-DNS-MANAGED-BLOCK:
  doh-altsvc` markers (already migrated, including a fresh install whose
  conf came from the current template directly);
- only replaces that block if the existing DoH listener section matches the
  exact known pre-migration (v0.4.0-beta.4) shape byte-for-byte -- anything
  else (an administrator's own edits to that block) is left untouched, and
  reported as skipped in the deployment message rather than guessed at;
- backs up `dnsdist.conf` first, runs `dnsdist --check-config` against the
  migrated result, and restores the backup if that check fails;
- records what happened in the deployment's message (visible in Encryption
  Settings' deployment history and `encryption.last_deployment()`).

Running it twice makes no further changes -- the second run sees its own
markers and returns immediately.

### Opt-in PowerDNS repository install (`alderpointdns install-enhanced-dnsdist`)

`sudo alderpointdns install-enhanced-dnsdist` (`app/dnsdist_upgrade.py`) is the
only way Alderpoint DNS will ever add the PowerDNS repository. It is never
invoked automatically — not from the `.deb` postinst, and not from the
unprivileged web process, which has no APT or `sudo` access.

**This command installs DoQ/DoH3 *capability* only.** It does not enable
either protocol — Alderpoint's own `doq_enabled`/`doh3_enabled` settings are
untouched, and no new listener starts until an administrator turns them on
in Encryption Settings and deploys. Running it:

1. Confirms the OS is Debian 13 (Trixie) and detects the architecture.
2. Exits immediately, unchanged, if `dnsdist --version` already reports both
   `dns-over-quic` and `dns-over-http3` (idempotent).
3. Resolves `repo.powerdns.com` before making any change.
4. Downloads the PowerDNS signing key (`https://repo.powerdns.com/FD380FBB-pub.asc`)
   with bounded retries and a fail-closed `curl`, rejects an empty or
   non-PGP file, and verifies its fingerprint against the one published at
   `repo.powerdns.com` and recorded in `app/dnsdist_upgrade.py`:

   ```
   9FAA A557 7E8F CF62 093D  036C 1B0C 6205 FD38 0FBB
   ```

   (downloaded and checked with `gpg --show-keys --with-fingerprint`
   against the PowerDNS Release Signing Key uid; re-verify independently
   before ever changing this constant).
5. Atomically installs the key to `/etc/apt/keyrings/dnsdist-21-pub.asc`
   and writes `/etc/apt/sources.list.d/pdns.list` (pointed at
   `trixie-dnsdist-21`) and `/etc/apt/preferences.d/dnsdist-21` (pin
   priority 600).
6. Runs `apt-get update` and confirms `apt-cache policy dnsdist` selects a
   `2.1.x` candidate that actually originates from `repo.powerdns.com`.
7. Backs up `/etc/dnsdist`, `/etc/systemd/system/dnsdist.service.d`, and
   `/etc/alderpointdns/certs` to `/var/lib/alderpointdns/backups/`.
8. Simulates the package operation (`apt-get install -s`) and refuses to
   proceed if it would remove Alderpoint DNS, BIND, or dnsdist itself.
9. Installs with `--force-confold` so Alderpoint's own
   locally-managed `/etc/dnsdist/dnsdist.conf` is preserved rather than
   replaced by the package maintainer's default configuration.
10. Requires the newly-installed `dnsdist --version` to report both
    `dns-over-quic` and `dns-over-http3`, runs
    `dnsdist --check-config`, restarts dnsdist, and verifies `dnsdist`,
    `named`, `alderpointdns`, and `alderpointdns-analytics` are all active,
    then runs a baseline plain-DNS query.

Any failure at any step restores the backed-up configuration where safe and
prints the exact manual rollback commands (including removing the APT
source entirely and reinstalling Debian's own `dnsdist` package) — it never
reports success on a partially-completed run.

Adding this repository changes where dnsdist security updates come from:
`apt upgrade` will now pull dnsdist from `repo.powerdns.com` instead of
Debian's own archive. To roll back to Debian's stock package:

```sh
sudo rm -f /etc/apt/sources.list.d/pdns.list /etc/apt/preferences.d/dnsdist-21 /etc/apt/keyrings/dnsdist-21-pub.asc
sudo apt-get update
sudo apt-get install -y --allow-downgrades dnsdist
sudo systemctl restart dnsdist
```

`alderpointdns dnsdist-capabilities` is a read-only diagnostic that reports
the installed dnsdist version, its APT origin, and DoH/DoT/DoQ/DoH3/DNSCrypt
support without changing anything.

### Firewall ports

| Protocol | Port |
| --- | --- |
| DoH | TCP 443 |
| DoH3 | UDP 443 |
| DoT | TCP 853 |
| DoQ | UDP 853 |

TCP and UDP listeners can share the same numeric port (443, 853) — they are
independent sockets and must both be opened if both transports are in use.
Certificate trust requirements are the same as DoH/DoT: clients must trust
the certificate `alderpointdns-lab.crt` (or your uploaded/CA-issued
certificate) presents.
