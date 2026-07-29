# Web application

BindGuard's web interface is a FastAPI/Jinja application served by
`bindguard.service`.

Current lab mode:

- URL: `http://127.0.0.1:3000`
- Service user: `bindguard`
- Listener: loopback only
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

Useful commands:

```sh
systemctl status bindguard --no-pager
systemctl restart bindguard
/opt/bindguard/tests/test_web_smoke.sh
```

The admin listener remains loopback-only until a management CIDR is supplied.
