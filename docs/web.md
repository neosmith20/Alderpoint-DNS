# Web application

BindGuard's web interface is a FastAPI/Jinja application served by
`bindguard.service`.

Current lab mode:

- URL: `http://<vm-lan-ip>:3000`
- Service user: `bindguard`
- Listener: `0.0.0.0:3000`
- Initial admin: none. The first administrator must be created through
  `/setup`.
- Password hashing: Argon2
- Session cookie: signed, `HttpOnly`, `SameSite=Strict`
- CSRF: required for mutating forms
- Login rate limiting: per source IP

The web process does not run as root. It can call only these exact privileged
commands through sudo:

```sh
/opt/bindguard/app/bindguard_compiler.py deploy
/opt/bindguard/app/bindguard_compiler.py deploy --no-download
/opt/bindguard/app/bindguard_compiler.py update-sources
```

Blocklist management supports add, inline edit, enable/disable, delete,
single-source update, update-all, and compile/deploy. Single-source updates are
unprivileged because they only write BindGuard's database and download cache;
deployment remains privileged and enumerated.

Useful commands:

```sh
systemctl status bindguard --no-pager
systemctl restart bindguard
/opt/bindguard/tests/test_web_smoke.sh
```

The admin listener binds to `0.0.0.0:3000` and requires a BindGuard admin
session. pfSense VLAN/firewall rules are responsible for restricting network
reachability to the management UI.
