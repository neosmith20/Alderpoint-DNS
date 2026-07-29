# BindGuard Handoff

Created: 2026-07-29

Superseded: 2026-07-29 by `/opt/bindguard/AGENT_PROGRESS.md`.
The user explicitly resumed the backlog after this handoff was written; use
`AGENT_PROGRESS.md` and the Git history as the current source of truth.

## Stop State

The user interrupted implementation and explicitly requested no further changes except this handoff file.

Do not continue implementation until the user asks to resume.

One command was aborted while attempting to wire Query Log partial refresh and CSS. Treat the repository as possibly partially modified and inspect it before resuming.

## Original Development Request

Continue BindGuard development autonomously from the live VM and current repository state.

Initial required steps:

- Read all existing project documentation.
- Inspect Git status and recent commits.
- Preserve the just-completed Local DNS work.
- Run the existing acceptance suite.
- Do not redo validated work.
- Create `/opt/bindguard/AGENTS.md` as binding project guidance for this and future BindGuard work.
- Create `/opt/bindguard/docs/adguard-parity.md` after researching current AdGuard Home master, OpenAPI spec, configuration docs, and frontend structure.
- Fix dashboard response-time accuracy before cache tuning.
- Then continue into BIND cache management, Encryption Settings, Backup and Restore, Replication, Import/Migration, UI standards, testing, commits, and final reboot acceptance.

## Additional User-Reported Issues

The user then reported these concrete regressions:

1. Local DNS records are not returning IP addresses.
   - User added `adguard.mylan.network` and `adguard2.mylan.network`.
   - `nslookup` against BindGuard showed the server recognized the names but returned no IPv4 or IPv6 answer.
   - Expected behavior: Local DNS A/AAAA records saved through the UI must resolve to their configured IP addresses.
   - Reverse DNS/PTR must also be tested by querying the IP and confirming the hostname is returned.

2. Local DNS text overflow.
   - Some Local DNS page text extends outside cards/boxes/containers.
   - Expected behavior: values should wrap, truncate, or resize without page-level horizontal overflow.

3. Unnecessary confirmation and full-page refresh on Local DNS add/edit.
   - Routine Local DNS add/edit operations currently show a confirmation prompt.
   - Expected behavior:
     - Fill form.
     - Click Save.
     - Validate input.
     - Save without a separate confirmation.
     - Avoid a full-page refresh where practical.
     - Show brief success/error notification.
     - Records remain editable after save.

4. Query Log Auto-Refresh does not persist.
   - Toggling Auto-Refresh reloads the whole page.
   - After reload, Auto-Refresh is no longer selected.
   - Expected behavior:
     - Auto-refresh updates only query-log data.
     - It does not reload the complete page.
     - The enabled/disabled state persists until the user changes it.

## State Inspected

Repository:

- CWD: `/root`
- Project: `/opt/bindguard`
- Git status before edits: clean.
- Recent commits:
  - `c61d1e6 Add Local DNS records and client aliases`
  - `e2c3c6e Redesign web interface as DNS appliance dashboard`
  - `2953448 Add native DNS analytics dashboard`
  - `264c426 Fix DNS settings layout overflow`
  - `443cad7 Enable PROXYv2 dnsdist frontend`
  - `7443770 Add blocklist edit and single-source update`
  - `92dd1b7 Prepare per-network policy schema`
  - `dec6ab1 Add curated public blocklist catalog`

Read docs:

- `/opt/bindguard/README.md`
- `/opt/bindguard/CHANGELOG.md`
- `/opt/bindguard/docs/progress.md`
- `/opt/bindguard/docs/architecture.md`
- `/opt/bindguard/docs/testing.md`
- `/opt/bindguard/docs/install.md`
- `/opt/bindguard/docs/known-limitations.md`
- `/opt/bindguard/docs/recovery.md`
- `/opt/bindguard/docs/filtering.md`
- `/opt/bindguard/docs/bind-backend.md`
- `/opt/bindguard/docs/database.md`
- `/opt/bindguard/docs/issues.md`
- `/opt/bindguard/docs/baseline.md`
- `/opt/bindguard/docs/configuration.md`
- `/opt/bindguard/docs/dnsdist.md`
- `/opt/bindguard/docs/security.md`
- `/opt/bindguard/docs/web.md`

Important documented Local DNS baseline:

- Local DNS default domain is `home.arpa`.
- Local DNS rejects `.local`.
- SQLite stores A, AAAA, PTR, CNAME, TTL, comments, enabled state, automatic PTR links, client aliases, and deployment results.
- Generated authoritative zones are separate from RPZ.
- Generated include: `/var/lib/bindguard/compiled/bind/local-zones.conf`.
- Generated zone files: `/var/lib/bindguard/compiled/bind/local/`.
- Local DNS mutations deploy through the staged no-download compiler path.

## Acceptance Suite Result Before Fixes

Command run:

```sh
/opt/bindguard/tests/test_acceptance.sh
```

Result: failed.

Failure:

```text
RuntimeError: forward lookup failed for bindguard.home.arpa
```

Stack path:

- `/opt/bindguard/app/bindguard_compiler.py`
- `deploy(download=not args.no_download)`
- `local_dns.deploy_zones(conn)`
- `local_dns.validate_dns_results(db)`

Earlier portions passed before failure:

- BIND backend tests passed.
- dnsdist frontend tests passed.
- Blocklist deploy unit portion began and then failed during deploy validation.

The failure is consistent with a Local DNS deployment validation/query timing or zone-generation issue.

## Issues Identified

### 1. Local DNS only generated the configured internal forward zone

File:

- `/opt/bindguard/app/local_dns.py`

Function:

- `build_zone_files`

Observed code behavior:

```python
forward_records = [
    row for row in enabled
    if row["record_type"] in {"A", "AAAA", "CNAME"}
    and row["fqdn"].endswith("." + domain)
]
zones = [ZoneFile(domain, ...)]
```

This means advanced records outside the configured internal domain, such as:

- `adguard.mylan.network`
- `adguard2.mylan.network`

are stored in SQLite but not emitted into any authoritative forward zone unless the Local DNS internal domain is changed to `mylan.network`.

Live query observed:

```sh
dig @127.0.0.1 -p 5353 adguard.mylan.network A +noall +answer +authority +comments
dig @127.0.0.1 -p 53 adguard.mylan.network A +noall +answer +authority +comments
```

Both returned NOERROR/NODATA with public Cloudflare SOA authority for `mylan.network`, not a BindGuard authoritative answer.

Expected fix:

- Emit managed forward zones for advanced FQDN records outside the internal domain.
- For `adguard.mylan.network`, create an authoritative `mylan.network` zone containing `adguard A/AAAA ...`.
- Keep the configured internal domain zone (`home.arpa`) even when empty.
- Do not fake parity or mark behavior complete without real DNS answers.

Architectural warning:

- Creating an authoritative zone for `mylan.network` means BindGuard becomes authoritative for that entire zone for clients using BindGuard. If public records under `mylan.network` must still resolve publicly, this needs split-horizon handling, explicit forwarding exceptions, or a more targeted rewrite architecture. For the user-reported Local DNS behavior, authoritative local handling is the immediate expected outcome.

### 2. Local DNS validation can race BIND reconfiguration

File:

- `/opt/bindguard/app/local_dns.py`

Function:

- `validate_dns_results`

Observed failure:

- Acceptance failed with `forward lookup failed for bindguard.home.arpa`.
- Immediately afterward, a manual `dig @127.0.0.1 -p 5353 bindguard.home.arpa A` returned:

```text
bindguard.home.arpa. 300 IN A 172.16.43.101
```

This suggests post-`rndc reconfig` / `rndc reload` validation can run before BIND is fully serving the new zone.

Expected fix:

- Retry validation for a short bounded period.
- Use DNS answer timestamps, not deployment delay, for latency work later.
- Keep validation strict: fail if the answer does not appear after retries.

### 3. Reverse DNS validation needs broader coverage

File:

- `/opt/bindguard/app/local_dns.py`

Function:

- `validate_dns_results`

Current behavior:

- Validates enabled A/AAAA rows up to a low limit.
- Reverse lookup only checked if `ptr_record_id` exists.

Expected follow-up:

- Ensure PTR records created for user-added hosts are validated.
- Add tests for explicit PTR records and automatic PTR records.
- Run direct `dig -x` checks against both backend (`127.0.0.1:5353`) and frontend (`127.0.0.1:53`).

### 4. Local DNS page routine forms use confirmation prompts

File:

- `/opt/bindguard/web/templates/local_dns.html`

Problematic `data-confirm` usage:

- Add host form.
- Advanced record form.
- Record edit form.
- Record toggle form.
- Possibly alias delete form.

Expected fix:

- Remove confirmation prompts from routine add/edit/toggle flows.
- Keep confirmation for destructive operations such as delete, bulk import, internal-domain change, and server identity creation if desired.
- Add normal success/error feedback. A full AJAX implementation was planned but not completed.

### 5. Local DNS page overflow risk

Files:

- `/opt/bindguard/web/templates/local_dns.html`
- `/opt/bindguard/web/static/app.css`

Expected fix:

- Apply wrapping classes to long FQDN, IP, target, and comment table cells.
- Add/reuse `.wrap-anywhere { overflow-wrap: anywhere; word-break: break-word; min-width: 0; }`.
- Verify at desktop and mobile widths with existing web smoke test.

### 6. Query Log auto-refresh reloads whole page and loses state

Files:

- `/opt/bindguard/web/static/app.js`
- `/opt/bindguard/web/templates/query_log.html`
- `/opt/bindguard/app/webapp.py`

Current JS behavior:

```javascript
refreshTimer = refreshToggle.checked ? setInterval(() => window.location.reload(), 10000) : null;
```

Expected fix:

- Persist checkbox state in `sessionStorage`.
- Refresh only a result container, not the whole page.
- Add an authenticated partial endpoint such as `/query-log/partial`.
- Keep current filters and page query params when refreshing.

## Files and Functions Needing Modification

Backend Local DNS:

- `/opt/bindguard/app/local_dns.py`
  - Add `forward_zone_for_fqdn(fqdn, internal_domain)`.
  - Update `build_zone_files`.
  - Add retry helper, e.g. `dig_contains`.
  - Update `validate_dns_results`.

Web backend:

- `/opt/bindguard/app/webapp.py`
  - Add helper `query_log_context(request)`.
  - Change `/query-log` to use helper.
  - Add `/query-log/partial` route rendering the table partial.
  - Later: add AJAX/JSON Local DNS mutation endpoints or progressive enhancement if implementing no-full-page-save fully.

Templates:

- `/opt/bindguard/web/templates/local_dns.html`
  - Remove routine `data-confirm` prompts.
  - Add wrapping classes to long cells.
  - Optional: add data hooks for async local DNS form submission.

- `/opt/bindguard/web/templates/query_log.html`
  - Wrap results in `#queryLogResults`.
  - Use `data-refresh-target` and `data-refresh-url`.
  - Include a partial.

- `/opt/bindguard/web/templates/query_log_results.html`
  - New partial for the query-log result table.

Static assets:

- `/opt/bindguard/web/static/app.js`
  - Replace full-page auto-refresh with targeted `fetch`.
  - Persist enabled state in `sessionStorage`.
  - Optional later: add Local DNS form toast behavior.

- `/opt/bindguard/web/static/app.css`
  - Add `.wrap-anywhere` if not already present.
  - Ensure table cells and form grids do not overflow.

Tests:

- `/opt/bindguard/tests/test_local_dns.py`
  - Add test for external forward zone generation, e.g. `adguard.mylan.network`.
  - Add test for forward zone file content.
  - Add test that validation retry succeeds after transient NODATA/failure.
  - Add explicit PTR validation test.

- `/opt/bindguard/tests/test_web_smoke.sh`
  - Add checks that Local DNS routine add/edit forms no longer contain `data-confirm`.
  - Add checks that Query Log has `queryLogResults`, `/query-log/partial`, and stateful auto-refresh JS.
  - Add overflow checks for Local DNS long content.

Docs:

- `/opt/bindguard/docs/progress.md`
- `/opt/bindguard/docs/testing.md`
- `/opt/bindguard/docs/web.md`
- `/opt/bindguard/docs/known-limitations.md`
  - Update after verified fixes.

Required but not yet created:

- `/opt/bindguard/AGENTS.md`
- `/opt/bindguard/docs/adguard-parity.md`

## Code/Patches Already Prepared or Applied

### Applied successfully: `/opt/bindguard/app/local_dns.py`

A command successfully modified this file.

Intended inserted function:

```python
def forward_zone_for_fqdn(fqdn: str, internal_domain: str) -> str:
    if fqdn == internal_domain or fqdn.endswith("." + internal_domain):
        return internal_domain
    labels = fqdn.split(".")
    if len(labels) < 3:
        return fqdn
    return ".".join(labels[1:])
```

Intended replacement for `build_zone_files`:

```python
def build_zone_files(conn: sqlite3.Connection, stage: Path, serial: int | None = None) -> list[ZoneFile]:
    cfg = settings(conn)
    domain = normalize_domain(cfg.get("internal_domain", DEFAULT_DOMAIN))
    default_ttl = validate_ttl(cfg.get("default_ttl", 300))
    zone_serial = serial or next_serial(conn)
    enabled = list(conn.execute("SELECT * FROM local_dns_records WHERE enabled=1 ORDER BY fqdn, record_type, value"))
    forward: dict[str, list[sqlite3.Row]] = {domain: []}
    for row in enabled:
        if row["record_type"] in {"A", "AAAA", "CNAME"}:
            zone = forward_zone_for_fqdn(row["fqdn"], domain)
            forward.setdefault(zone, []).append(row)
    zones = [
        ZoneFile(zone, stage / "local" / f"{zone}.zone", render_zone(zone, rows, zone_serial, default_ttl))
        for zone, rows in sorted(forward.items())
    ]
    reverse: dict[str, list[sqlite3.Row]] = {}
    for row in enabled:
        if row["record_type"] == "PTR":
            zone = ".".join(row["fqdn"].split(".")[1:])
            reverse.setdefault(zone, []).append(row)
    for zone, rows in sorted(reverse.items()):
        zones.append(ZoneFile(zone, stage / "local" / f"{zone}.zone", render_zone(zone, rows, zone_serial, default_ttl)))
    return zones
```

Intended inserted retry helper and validation replacement:

```python
def dig_contains(command: list[str], expected: str, attempts: int = 5) -> bool:
    expected_lower = expected.rstrip(".").lower()
    for attempt in range(attempts):
        proc = run(command, check=False)
        output = proc.stdout.rstrip(".\n").lower()
        if proc.returncode == 0 and expected_lower in output:
            return True
        if attempt + 1 < attempts:
            time.sleep(0.35)
    return False


def validate_dns_results(conn: sqlite3.Connection) -> None:
    rows = list(conn.execute("SELECT * FROM local_dns_records WHERE enabled=1 AND record_type IN ('A','AAAA') ORDER BY id LIMIT 20"))
    for row in rows:
        if not dig_contains(["dig", "@127.0.0.1", "-p", "5353", row["fqdn"], row["record_type"], "+short", "+time=2", "+tries=1"], row["value"]):
            raise RuntimeError(f"forward lookup failed for {row['fqdn']}")
        ptr = conn.execute("SELECT fqdn FROM local_dns_records WHERE id=?", (row["ptr_record_id"],)).fetchone() if row["ptr_record_id"] else None
        if ptr:
            if not dig_contains(["dig", "@127.0.0.1", "-p", "5353", "-x", row["value"], "+short", "+time=2", "+tries=1"], row["fqdn"]):
                raise RuntimeError(f"reverse lookup failed for {row['value']}")
```

Warning:

- This change needs review and tests. It creates parent authoritative zones for out-of-domain records. Confirm this is the desired split-horizon behavior for `mylan.network`.

### Applied successfully: `/opt/bindguard/web/templates/local_dns.html`

A command successfully modified this file.

Completed/planned changes:

- Removed `data-confirm` from:
  - Add Host form.
  - Advanced Record form.
  - Record toggle form.
  - Record edit form.
  - Alias delete form.

- Kept destructive confirmation for record delete:

```html
data-confirm="Delete this local DNS record and deploy?"
```

- Added wrapping class to Local DNS table cells:

```html
<td class="mono wrap-anywhere" title="{{ record.fqdn }}">{{ record.fqdn }}</td>
<td class="mono wrap-anywhere" title="{{ record.value }}">{{ record.value }}</td>
<td class="wrap-anywhere">{{ record.comment }}</td>
```

Warning:

- The user also requested no full-page refresh and brief notifications. That has not been completed for Local DNS forms. Current form submissions likely still redirect after save.

### Applied successfully: `/opt/bindguard/web/templates/query_log.html`

A command first made a bad string-edit that introduced malformed HTML. A later successful command rewrote the full file cleanly to include a results container:

```html
<div id="queryLogResults" data-refresh-url="/query-log/partial">
  {% include "query_log_results.html" %}
</div>
```

Verify this file before resuming.

### Applied successfully: `/opt/bindguard/web/templates/query_log_results.html`

A new partial was created with:

- Query Log results table.
- Empty state.
- Pagination.
- Wrapping classes on client/domain/block-source cells.

Verify the file exists and is syntactically valid.

### Aborted/uncertain: `/opt/bindguard/app/webapp.py`, `/opt/bindguard/web/static/app.js`, `/opt/bindguard/web/static/app.css`

The command intended to modify these files was aborted by the user. It may not have executed, or it may have partially executed. Inspect before editing.

Intended webapp patch:

```python
def query_log_context(request: Request) -> dict[str, Any]:
    limit = min(500, max(10, int(request.query_params.get("limit", "50"))))
    page = max(1, int(request.query_params.get("page", "1")))
    filters = {
        "search": request.query_params.get("search", ""),
        "client": request.query_params.get("client", ""),
        "domain": request.query_params.get("domain", ""),
        "qtype": request.query_params.get("qtype", ""),
        "protocol": request.query_params.get("protocol", ""),
        "blocked": request.query_params.get("blocked", ""),
        "rcode": request.query_params.get("rcode", ""),
    }
    return {"log": analytics.query_log(filters, page, limit)}


@app.get("/query-log", response_class=HTMLResponse)
def query_log(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "query_log.html", **query_log_context(request))


@app.get("/query-log/partial", response_class=HTMLResponse)
def query_log_partial(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "query_log_results.html", **query_log_context(request))
```

Intended app.js patch:

```javascript
const refreshToggle = document.getElementById('autoRefresh');
let refreshTimer = null;
if (refreshToggle) {
  const key = `bindguardAutoRefresh:${window.location.pathname}`;
  const target = document.getElementById(refreshToggle.dataset.refreshTarget || '');
  const refresh = async () => {
    if (!target || !target.dataset.refreshUrl) {
      window.location.reload();
      return;
    }
    const url = new URL(target.dataset.refreshUrl, window.location.origin);
    url.search = window.location.search;
    const response = await fetch(url, { headers: { 'X-Requested-With': 'BindGuardAutoRefresh' } });
    if (response.ok) target.innerHTML = await response.text();
  };
  const schedule = () => {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = refreshToggle.checked ? setInterval(refresh, 10000) : null;
  };
  refreshToggle.checked = sessionStorage.getItem(key) === '1';
  refreshToggle.addEventListener('change', () => {
    sessionStorage.setItem(key, refreshToggle.checked ? '1' : '0');
    schedule();
    if (refreshToggle.checked) refresh();
  });
  schedule();
}
```

Intended CSS patch:

```css
.wrap-anywhere {
  overflow-wrap: anywhere;
  word-break: break-word;
  min-width: 0;
}
```

## Changes Completed Before Stop

Confirmed by successful command output:

- Read project documentation.
- Inspected Git status/recent commits.
- Ran acceptance suite and captured Local DNS validation failure.
- Diagnosed out-of-domain Local DNS records not being emitted into authoritative zones.
- Diagnosed validation race for `bindguard.home.arpa`.
- Modified `/opt/bindguard/app/local_dns.py` as described above.
- Modified `/opt/bindguard/web/templates/local_dns.html` as described above.
- Created/rewrote Query Log templates:
  - `/opt/bindguard/web/templates/query_log.html`
  - `/opt/bindguard/web/templates/query_log_results.html`

Not completed:

- Did not create `/opt/bindguard/AGENTS.md`.
- Did not create `/opt/bindguard/docs/adguard-parity.md`.
- Did not complete Query Log backend/JS/CSS wiring with certainty.
- Did not implement Local DNS AJAX save/toasts.
- Did not add tests.
- Did not rerun acceptance after changes.
- Did not restart services.
- Did not commit.

## Changes Still Remaining

Immediate next steps when user asks to resume:

1. Inspect current diff.

```sh
git -C /opt/bindguard status --short
git -C /opt/bindguard diff -- app/local_dns.py web/templates/local_dns.html web/templates/query_log.html web/templates/query_log_results.html app/webapp.py web/static/app.js web/static/app.css
```

2. Verify whether the aborted command changed these files:

```sh
rg -n "query_log_context|/query-log/partial|bindguardAutoRefresh|wrap-anywhere" /opt/bindguard/app/webapp.py /opt/bindguard/web/static/app.js /opt/bindguard/web/static/app.css
```

3. If not present, apply the intended `webapp.py`, `app.js`, and `app.css` changes listed above.

4. Add tests:

- External forward zone generation:
  - Add `A adguard.mylan.network 172.16.43.x`.
  - Assert zone set includes `mylan.network`.
  - Assert zone content contains `adguard ... A ...`.

- Validation retry:
  - Mock `dig` failure for first attempt and success on subsequent attempt.
  - Assert `validate_dns_results` succeeds.

- PTR:
  - Assert automatic PTR zone content.
  - Assert validation checks reverse lookup for automatic PTR.

- Query Log:
  - Assert `/query-log/partial` renders.
  - Assert `queryLogResults` exists on `/query-log`.
  - Assert JS no longer uses `window.location.reload()` for the normal refresh path.
  - Assert `sessionStorage` persistence code exists.

- Local DNS UI:
  - Assert routine add/edit/toggle forms do not have `data-confirm`.
  - Assert destructive delete still has confirmation.
  - Assert `.wrap-anywhere` class exists and is used.

5. Run focused tests.

```sh
python3 -B /opt/bindguard/tests/test_local_dns.py
/opt/bindguard/tests/test_web_smoke.sh
```

6. Deploy/restart only if tests justify it.

Likely deployment command:

```sh
/opt/bindguard/app/bindguard_compiler.py deploy --no-download
systemctl restart bindguard
```

7. Functional DNS verification:

Use actual user records if present:

```sh
dig @127.0.0.1 -p 5353 adguard.mylan.network A +noall +answer +authority +comments
dig @127.0.0.1 -p 53 adguard.mylan.network A +noall +answer +authority +comments
dig @127.0.0.1 -p 5353 adguard2.mylan.network A +noall +answer +authority +comments
dig @127.0.0.1 -p 53 adguard2.mylan.network A +noall +answer +authority +comments
dig @127.0.0.1 -p 5353 -x <adguard-ip> +short
dig @127.0.0.1 -p 53 -x <adguard-ip> +short
```

Also verify known existing record:

```sh
dig @127.0.0.1 -p 5353 bindguard.home.arpa A +short
dig @127.0.0.1 -p 53 bindguard.home.arpa A +short
dig @127.0.0.1 -p 5353 -x 172.16.43.101 +short
dig @127.0.0.1 -p 53 -x 172.16.43.101 +short
```

8. Run complete acceptance suite.

```sh
/opt/bindguard/tests/test_acceptance.sh
```

9. Update docs:

- `/opt/bindguard/docs/progress.md`
- `/opt/bindguard/docs/testing.md`
- `/opt/bindguard/docs/web.md`
- `/opt/bindguard/docs/known-limitations.md`

10. Create `/opt/bindguard/AGENTS.md` per user request.

11. Commit only after full acceptance passes.

## AGENTS.md Content Still Required

Create `/opt/bindguard/AGENTS.md` with binding guidance covering:

- Scope: all application code, DBs, docs, generated config, systemd units, users, packages, tests, BIND/dnsdist config, TLS certs, backups, and project-owned VM files.
- Standing authorization for BindGuard-owned file operations, packages, repos, users/groups/ACLs/capabilities/sudoers, services, reboot, DB/migrations, self-signed certs/CAs, tests/captures/diagnostics/benchmarks, backups/rollback, local commits, subagents, and safe engineering/UI decisions.
- Do not ask permission for authorized BindGuard work.
- Ask only for actions outside VM, unavailable credentials/private keys/public hostname/external accounts, destruction of unrelated data, public exposure/production routing changes, or unavoidable subjective decisions.
- Missing optional deployment values are not blockers.
- Milestones are checkpoints, not stopping points.
- Required engineering behavior for configuration changes:
  1. Staging.
  2. Validation.
  3. Backup.
  4. Atomic activation.
  5. Service health verification.
  6. Functional DNS testing.
  7. Automatic rollback.
  8. Recorded deployment result.
- Never commit secrets, live private keys, backup archives, database snapshots, or audit captures.
- Plain UDP/TCP DNS on port 53 must remain functional.
- Host maintenance resolution must remain independent of BIND/dnsdist.
- DNS must continue if web app, analytics, backup, or replication fails.
- Update tests/docs with every user-facing feature.
- Run complete acceptance before committing completed workstream.

## AdGuard Parity Audit Still Required

Create `/opt/bindguard/docs/adguard-parity.md`.

Must research current AdGuard Home:

- Master branch.
- Current OpenAPI specification.
- Configuration documentation.
- Current frontend structure.

Use AdGuard Home as functional/usability reference only. Do not copy source, CSS, assets, icons, logo, or branded text.

Matrix columns:

- AdGuard feature or setting.
- Where it appears in AdGuard.
- BindGuard equivalent.
- BindGuard implementation location.
- Current status: complete, partial, planned, intentionally not applicable.
- Missing tests.
- Notes explaining architectural differences.

Minimum feature coverage is exactly as listed in the user request, including dashboard/protection pause, stats/query log/filtering reasons, subscriptions, rewrites/Local DNS, client settings, per-client behavior, safe search, blocked services/schedules, DNS modes/upstreams/bootstrap/fallback/private reverse/forward-by-domain, DNSSEC/ECS/IPv6/rate limits/blocking modes/cache/encrypted DNS/TLS/admin HTTPS/Apple profiles/DHCP/auth/system/backup/restore/import/export/replication/disaster recovery.

## Response-Time Accuracy Work Still Required

Do not start cache tuning until this is complete.

Required audit:

- Every latency field used by collector/dashboard.
- Raw dnsdist field name.
- Raw value.
- Source unit.
- Database unit.
- API unit.
- Display unit.
- Protobuf query/response timestamp conversion.
- UDP/TCP/DoH/DoT/DoQ/DoH3 behavior.
- Ensure delayed telemetry delivery is not counted as DNS latency.

Expected design:

- Single internal canonical unit, preferably integer microseconds.
- Convert only at API/display boundary.

Required tests:

- `4058.9` microseconds displays as about `4.1 ms`.
- One-second responses display as `1000 ms`.
- No microsecond/millisecond multiplication error.
- No negative/impossible latency.
- Counter resets do not corrupt aggregates.
- Telemetry queue delay is not counted as DNS processing time.

Required controlled comparisons:

- First uncached query.
- Repeated cached query.
- Direct BIND backend.
- dnsdist frontend.
- Dashboard value.
- Query-log value.

## Important Assumptions and Warnings

- Network access is restricted in the sandbox; use approved/escalated commands as needed for BindGuard-owned VM actions.
- `/opt/bindguard` is outside the default writable root, but the user explicitly authorized BindGuard-owned changes. Previous successful edits used escalation.
- `sqlite3` CLI is not installed; use Python `sqlite3` for DB inspection unless installing the CLI is needed.
- Reading some `/var/lib/bindguard` files may require escalation.
- Existing Local DNS work is validated as a foundation; preserve it and fix regressions without replacing the design.
- Do not commit until tests pass.
- Do not reboot until a completed major workstream needs final reboot acceptance.
- Do not proceed to cache/performance tuning until latency metrics are trustworthy.
- Query Log template was rewritten after an accidental malformed intermediate state, but still must be verified before running service tests.
