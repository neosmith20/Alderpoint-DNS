# Security

- The web process runs as `bindguard`, not root.
- Privileged web operations are restricted by `/etc/sudoers.d/bindguard` to
  exact compiler commands.
- The admin UI requires authentication and relies on pfSense VLAN/firewall
  policy for network reachability.
- No default administrator exists.
- Passwords are hashed with Argon2.
- Session cookies are signed, `HttpOnly`, and `SameSite=Strict`.
- CSRF tokens are required for mutating forms.
- dnsdist ACLs allow RFC1918 private networks by default, with an explicit
  environment switch for allow-all mode.
- BIND listens only on loopback backend ports.
- AppArmor remains enabled for BIND.

Lab HTTP mode does not mark cookies `Secure`; enable that when admin HTTPS is
configured.
