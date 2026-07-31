# Migration Guide

Alderpoint DNS supports preview-first imports from:

- AdGuard Home YAML or read-only API
- Pi-hole text/list exports
- Generic hosts files
- BIND zone files
- CSV/XLSX
- Alderpoint DNS-native JSON

Migration rules:

- Parse first, preview second, apply only what is selected.
- Existing records are not silently overwritten.
- Conflicts, duplicates, skipped entries, unsupported syntax, and warnings are
  shown before apply.
- A verified backup is taken before apply; if the backup fails, the apply is
  refused.
- Unsupported source features are documented rather than fabricated.
- Migration creation, status polling, preview, apply, cancel, and report links
  all use `/import/jobs/{job_id}/...`; `/import/migration` is a literal entry
  point and is not eligible for integer job-ID parsing.

## AdGuard Home mapping

| AdGuard Home object | Alderpoint DNS destination |
| --- | --- |
| `filters` (subscription URLs) | Blocklist sources; name, URL, and enabled state preserved; the list name/URL is mapped onto a managed category (`malware`, `adult_content`, `iot_telemetry`) when it cleanly matches, else `ads_trackers` |
| `whitelist_filters` (allowlist subscriptions) | Explicit unsupported finding (Alderpoint DNS has custom allow rules, not allowlist subscriptions) |
| `user_rules`: `\|\|domain^`, `\|domain^`, `@@…` | Custom block/allow rules; exact vs domain+subdomains anchoring preserved |
| `user_rules`: plain domain | Custom block rule with AdGuard semantics (domain **and** subdomains) |
| `user_rules`: hosts lines with `0.0.0.0` / `::` | Exact-host custom block rules (one per hostname; inline `#` comments kept) |
| `user_rules`: hosts lines with any other address | Exact-host rewrite rules answering exactly that address (A vs AAAA preserved) |
| `user_rules`: `! …` and `# …` comments | Comment rules (kept for organization, no DNS effect, never counted as failures) |
| `user_rules`: `/regex/`, `@@/regex/` | Regex block/allow rules; validated against the POSIX-ERE-safe subset, otherwise stored inactive with the exact reason |
| `user_rules`: `$important` | Priority preserved (allow/block conflict resolution) |
| `user_rules`: `$dnsrewrite=<IP>` | Rewrite rule following the base rule's exact/subdomain anchor |
| `user_rules`: `$client=…` | Stored inactive, shown under Client-scoped items (no per-client enforcement exists) |
| `user_rules`: other modifiers (`$dnstype`, `$ctag`, `$denyallow`, …) | Stored inactive with the exact reason; a narrowing modifier is never stripped to activate a broadened rule |
| `filtering.rewrites`, A/AAAA answer, non-wildcard name | Local DNS A/AAAA record, regardless of whether the name falls under Alderpoint DNS's configured internal domain -- AdGuard's DNS Rewrites are AdGuard's own Local-DNS-equivalent feature, and Local DNS already supports arbitrary external names via an auto-created managed forward zone |
| `filtering.rewrites`, `*.name` wildcard, A/AAAA answer | Subdomain rewrite custom rule (`\|\|name^$dnsrewrite=IP`) if enabled -- Local DNS has no wildcard record type, so this is the only rewrite form that still maps to a custom rule; a disabled wildcard rewrite is reported rather than imported as an active rule (Alderpoint DNS's custom-rule apply path has no "disabled dnsrewrite" state) |
| `filtering.rewrites`, domain answer (CNAME-style) | Local DNS CNAME record when the target is a valid domain, else an unsupported finding; not restricted to the internal domain (an auto-created managed forward zone covers external names, same as any other advanced record) |
| `filtering.rewrites`, `*.name` wildcard, domain (CNAME-style) answer | Explicit unsupported finding (never silently converted to an exact record) |
| `filtering.rewrites`, answer of literal `A` or `AAAA` | AdGuard's own pass-through/exclusion sentinel (stop matching a broader rewrite for that query type); has no Alderpoint DNS equivalent and is reported, never read as a literal address or a single-label CNAME target |
| `filtering.rewrites`, per-rewrite `enabled: false` | Imported as a disabled (`enabled=0`) Local DNS record so it stays inactive rather than being silently activated |
| `filtering.rewrites_enabled: false` | Every rewrite is treated as disabled at the source, same as a per-item `enabled: false` |
| `rewrites` at the top level (schema versions that predate `filtering.rewrites`) | Read as a fallback if `filtering.rewrites` is absent |
| `user_rules`: `$dnsrewrite=NOERROR;CNAME;…` or other non-A/AAAA `$dnsrewrite` forms | Stored inactive with the exact reason (only plain A/AAAA address rewrites are representable as a custom rule) |
| `clients.persistent` name + IP/CIDR | Client alias (display label only) |
| Per-client settings (filtering, SafeSearch, upstreams, …) | Explicit client-scoped findings, never silently dropped |
| `dns.upstream_dns` / `dns.bootstrap_dns` | Upstream resolvers (plain/DoH translated; other schemes and `[/domain/]` routing reported as untranslatable) |

The AdGuard API path (`/import/migration/adguard/api`) uses the credentials
only for the read-only fetch. Only the sanitized base URL (scheme, host,
port — no userinfo, no query string) is ever stored on the job row. Fetches
are restricted to http/https including redirects, carry an 8-second
per-request timeout, and responses are size-capped.

### Local DNS rewrite outcomes

Every DNS rewrite that reaches the Local DNS destination is classified with
one of the following preview outcomes, so a bare "Applied" status is never
the only signal for what happened to a rewrite:

- **new** — no conflicting or identical record exists yet; will be created.
- **existing** — an identical record (same FQDN, type, and value) already
  exists; the import skips it rather than creating a duplicate.
- **conflicting** — the hostname already has a different record (a
  different address, or a CNAME/other-type clash); the new record is still
  added alongside it (Alderpoint DNS never silently overwrites an existing
  record), and the conflict is reported.
- **disabled at source** — the AdGuard rewrite was disabled per-item or by
  the global `filtering.rewrites_enabled` toggle; imported as a disabled
  Local DNS record rather than silently activated.
- **unsupported** — the rewrite cannot be represented (a wildcard
  CNAME-style rewrite, an unparseable answer, or AdGuard's `A`/`AAAA`
  pass-through sentinel); reported, never silently dropped.

Multiple valid answers for the same hostname (e.g. two A records, for basic
round-robin) are each their own item and are not treated as duplicates of
each other, though the second and later answers are flagged **conflicting**
since Alderpoint DNS's hostname-conflict check does not distinguish "another
valid answer" from "an unexpected extra record" — both are added, neither
overwrites the other.

Alderpoint DNS's migration rule that existing records are never silently
overwritten means a rewrite can never produce an **updated** Local DNS
record; a changed answer for an already-imported hostname is always a new,
separately reported **conflicting** item instead.

## Pi-hole mapping

The Pi-hole importer is a structured multi-section parser. Section headers
(`[whitelist]`, `# whitelist.txt`, `[regex whitelist]`, …) switch how bare
lines are interpreted; keyword lines work anywhere.

| Pi-hole object | Alderpoint DNS destination |
| --- | --- |
| adlists.list / URL lines | Blocklist sources |
| whitelist.txt domains / `whitelist <d>` | Custom allow rules, **exact-host** semantics |
| blacklist.txt domains / `blacklist <d>` | Custom block rules, **exact-host** semantics |
| regex.list lines / `regex <pattern>` | Regex block rules (Pi-hole regex is POSIX ERE and usually translates; incompatible patterns are stored inactive with the reason) |
| `regex whitelist <pattern>` / a regex-whitelist section | Regex allow rules |
| Wildcard idiom `(\.\|^)domain\.tld$` | Offered as a subdomain block of `domain.tld`; the original regex text is preserved in the rule comment |
| custom.list hosts lines | Local DNS A/AAAA records (Pi-hole "Local DNS records", not custom rewrites) |
| `cname=alias,target[,ttl]` | Local DNS CNAME records |
| Group assignment syntax or columns | Explicit findings under Client-scoped items (no equivalent), never dropped silently |
| Anything else | Explicit unsupported finding carrying the original line |

Plain-domain semantics differ deliberately: Pi-hole exact lists import with
exact-host matching (`plain_domain_subdomains=False`), while AdGuard plain
domains cover the domain and its subdomains. Conformance tests cover both.

## Preview, deselect, apply, rollback

1. **Upload/fetch** stages the source, stores the parsed translation on an
   import job, and redirects to the preview.
2. **Preview** (`GET /import/jobs/{id}/preview`) is pure: it classifies the
   stored translation and never creates, updates, or deletes any destination
   object, no matter how many times it is rendered. Every item shows the
   original source value, detected type, destination, normalized result,
   active/inactive outcome, and any warning or conflict (duplicate within the
   import, already exists, allow-vs-block conflict). Items carry stable
   `category:index` keys derived only from the stored translation, rendered
   as checkboxes; invalid/unsupported entries are import-as-inactive toggles.
   Category "select all" checkboxes and per-item checkboxes both feed the
   same `sel` form field.
3. **Apply** (`POST /import/jobs/{id}/apply`) validates all selected entries,
   takes the verified pre-import backup (failure aborts), then performs every
   database write in **one transaction**: custom rules through the
   `custom_filter_rules` model (stamped with `source_system` and
   `import_job_id`), blocklist sources, Local DNS records, client aliases,
   and upstream resolvers. Only after a successful apply does the normal
   validated deploy run.
4. **Failure handling**: if any stage fails, the transaction rolls back —
   no destination table keeps partial rows — and the job is marked `failed`
   with the exact stage in its message. If the apply succeeds but the deploy
   fails, deploy() itself restores the previously compiled configuration, the
   job is marked `deploy_failed`, and the operator can roll back the database
   writes or retry.
5. **Rollback** (`POST /import/jobs/{id}/rollback`) removes exactly what the
   apply created: `custom_filter_rules` rows by `import_job_id`, inserted
   Local DNS records, newly added sources/aliases/upstream resolvers, and
   restores the previous values of any source or alias the apply updated —
   then redeploys.

## Job result reporting

A migration job's status column stays a plain `applied` for state-machine
purposes (rollback, re-preview, etc.), but the job page and its `message`
never present that as an unqualified "Applied" when anything was skipped,
flagged, kept inactive, or left out by the operator. A separate
`result_label` -- one of `Applied`, `Applied with skipped duplicates`,
`Applied with conflicts`, `Applied with unsupported items`,
`Applied with user-deselected items` (or a combination), or `Failed` -- is
computed from the same counts and shown as the job's headline status.

The job's `message` breaks the result down per component, e.g.:

```text
Applied with user-deselected items

Blocklists: 12 created, 3 existing
Custom rules: 76 created
Local DNS: 2 created
Unsupported: 0
Deselected: 2
2 Local DNS records were not imported because Local DNS was deselected
```

Local DNS is always itemized explicitly, even at zero -- a silent zero
there (a migration reporting a plain "Applied" while every Local DNS record
was actually omitted) is exactly the failure mode this format guards
against. Deselecting an entire category is never folded into a generic "N
deselected" count: a dedicated sentence per category names the exact count,
e.g. "2 Local DNS records were not imported because Local DNS was
deselected".

## Reports

`GET /import/jobs/{id}/report` downloads a JSON report built from the stored
job report: counts for imported blocklists, block/allow/rewrite/regex rules
and comments, duplicates skipped, invalid and unsupported entries kept
inactive, user-deselected items (with a category-by-category breakdown in
`deselection_notes`), Local DNS conflicts, the computed `result_label`, and
failures. Reports are sanitized at write time and again at download time:
credential-named keys are dropped and every embedded URL loses its userinfo
and query string, so passwords and access tokens can never leave through a
report. AdGuard API passwords never enter job rows at all.

## Limits

- Uploads are capped at 10 MiB.
- Text imports are capped at 200,000 lines with a clear error.
- Individual lines longer than 2,048 characters become explicit findings
  instead of stored rules.

## Source limitations

- Pi-hole gravity database internals are not read directly; the importer
  covers the practical text exports listed above.
- AdGuard domain-specific upstream routing has no Alderpoint DNS equivalent yet.
- AdGuard allowlist subscriptions are reported for manual review because
  Alderpoint DNS has custom allow rules, not allowlist-subscription objects.
- Client-scoped rules and Pi-hole group assignments are preserved as explicit
  inactive findings; there is no per-client or per-group runtime enforcement.
