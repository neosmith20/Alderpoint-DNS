# Security

- The web process runs as `bindguard`, not root.
- Privileged web operations are restricted by `/etc/sudoers.d/bindguard` to
  exact compiler commands.
- The admin UI is loopback-only.
- No default administrator exists.
- Passwords are hashed with Argon2.
- Session cookies are signed, `HttpOnly`, and `SameSite=Strict`.
- CSRF tokens are required for mutating forms.
- dnsdist ACLs allow loopback only in lab mode.
- BIND listens only on loopback backend ports.
- AppArmor remains enabled for BIND.

Lab HTTP mode does not mark cookies `Secure`; enable that when admin HTTPS is
configured.
