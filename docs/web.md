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

The interface uses a shared dark-theme application shell across all admin
pages. The shell is defined in `web/templates/base.html`, reusable components
live in `web/templates/components.html`, and the visual system is maintained in
`web/static/app.css` with CSS custom properties for page background, panels,
borders, text, accent, success, warning, danger, blocked, malware, adult
category, spacing, radius, and shadows. Runtime JavaScript is local-only in
`web/static/app.js`; public CDNs are not used.

The dashboard is organized around DNS-appliance information hierarchy:

- Protection state and protection enable/disable action with confirmation.
- Manual refresh, auto-refresh control, last refresh timestamp, and a
  session-persisted time-range selector for last hour, last 24 hours, last
  seven days, and last 30 days.
- Primary metric cards for DNS queries, blocked queries, percentage blocked,
  active clients, average response time, and active filtering rules.
- Real sparklines and a responsive local canvas time-series chart using stored
  BindGuard analytics buckets only.
- Query outcome bars for allowed, blocked, and recorded policy categories.
- Ranked panels for clients, queried domains, blocked domains, query types,
  response codes, protocol usage, and clear unavailable states for upstream
  resolver data that is not yet stored.
- Recent activity and compact system-health chips with low-level details moved
  to `/system`.

The Query Log, Blocklists, Filters, Local DNS, DNS Settings, Statistics, System,
login, and setup pages all use the same card, table, badge, form, button,
empty-state, and confirmation styles. Long domains, IPv6 addresses, paths,
command names, version strings, and URLs use wrapping or deliberate local table
scrolling so they do not create page-level horizontal overflow.

The Query Log page supports search, pagination, auto-refresh, client/domain
filters, query type, protocol, allowed/blocked status, response code, and direct
creation of allow/block rules with confirmation and normal staged deployment.

Blocklist management supports add, inline edit, enable/disable, delete,
single-source update, update-all, and compile/deploy. Single-source updates are
unprivileged because they only write BindGuard's database and download cache;
deployment remains privileged and enumerated.

The Local DNS page supports:

- Internal domain settings, defaulting to `home.arpa`.
- Setup and page actions to create BindGuard's own forward and reverse records.
- Simple host entries that create A/AAAA records and optional automatic PTR
  records together.
- Advanced A, AAAA, PTR, and CNAME records with TTL, comments, and enabled
  state.
- Client aliases for dashboard/query-log display without changing DNS behavior.
- CSV preview/import/export and hosts-style preview.
- Last Local DNS deployment status, serial, validation output, and rollback
  result.

Every Local DNS mutation runs the normal no-download deployment path, which
stages generated zones, validates them, installs atomically, reloads BIND, and
records the result.

Useful commands:

```sh
systemctl status bindguard --no-pager
systemctl status bindguard-analytics --no-pager
systemctl restart bindguard
systemctl restart bindguard-analytics
/opt/bindguard/tests/test_web_smoke.sh
```

Responsive review targets are 1920, 1440, 1024, 768, 430, and 360 pixels wide.
The smoke test renders long domains, IPv6 clients, and long upstream URLs and
checks the shared no-overflow CSS contract, mobile navigation hooks, chart data
endpoint, local-only static assets, and dashboard/query-log/settings page
rendering.

Sanitized before-and-after screenshots are stored under `docs/screenshots/`:

- `dashboard-before-desktop.png`
- `dashboard-after-desktop.png`
- `dashboard-before-mobile.png`
- `dashboard-after-mobile.png`

The admin listener binds to `0.0.0.0:3000` and requires a BindGuard admin
session. pfSense VLAN/firewall rules are responsible for restricting network
reachability to the management UI.
