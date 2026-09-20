# Migration Guide

Alderpoint DNS v1.1.1 includes preview-first migration/import tooling for supported external DNS-filtering appliance formats, Pi-hole exports, generic hosts files, BIND zone files, CSV/XLSX data, and Alderpoint DNS-native exports.

The migration system is deliberately conservative:

- Parse first, preview second, apply only what the operator selects.
- Existing records are not silently overwritten.
- Conflicts, duplicates, skipped entries, unsupported syntax, and warnings are shown before apply.
- A verified backup is taken before apply; if that backup fails, the apply is refused.
- Unsupported source features are reported rather than silently approximated.
- Import jobs use staged application and normal validated deployment paths.

## Supported destination types

Depending on the source format, imported material may map into:

- blocklist sources
- custom block/allow rules
- DNS rewrite rules
- Local DNS A/AAAA/CNAME records
- client aliases or configured clients
- upstream resolvers
- inactive findings for source behavior that cannot be represented safely

Source-specific semantics are preserved where practical. A narrowing source rule is never intentionally broadened merely to make it importable. Unsupported or ambiguous entries are retained as explicit findings when possible.

## Local DNS outcomes

A Local DNS item in migration preview is classified before apply. Common outcomes include:

- **new** — no conflicting or identical record exists yet;
- **existing** — an identical record is already present and is skipped rather than duplicated;
- **conflicting** — the hostname already has a different record and the conflict is surfaced;
- **disabled at source** — retained inactive where the destination model supports that state;
- **unsupported** — the source behavior cannot be represented safely and is reported rather than silently dropped.

Alderpoint DNS does not silently overwrite an existing Local DNS record during migration.

## Pi-hole mapping

The Pi-hole importer accepts practical text/list exports and structured sections.

| Pi-hole object | Alderpoint DNS destination |
| --- | --- |
| adlists/list URL lines | Blocklist sources |
| whitelist domains | Custom allow rules with exact-host semantics |
| blacklist domains | Custom block rules with exact-host semantics |
| regex entries | Regex block/allow rules where compatible |
| custom.list hosts lines | Local DNS A/AAAA records |
| `cname=alias,target[,ttl]` | Local DNS CNAME records |
| group-assignment data without a direct destination | Explicit inactive findings |
| unsupported input | Explicit finding carrying the original source line |

Pi-hole gravity database internals are not read directly; supported import paths use practical exported data rather than depending on another product's private database layout.

## Preview, deselect, apply, rollback

1. **Upload/fetch** stages the source and stores a parsed translation in an import job.
2. **Preview** is non-destructive. It classifies the stored translation and shows the detected source item, destination, normalized result, active/inactive outcome, warning, duplicate, or conflict state.
3. **Apply** validates the selected entries, takes the required pre-import backup, performs the destination writes transactionally where supported, and then runs the normal validated runtime deploy.
4. **Failure handling** rolls back transactional writes and preserves the previously working runtime when deployment fails.
5. **Rollback** removes or restores exactly the material associated with the migration job and redeploys the resulting configuration.

## Reporting

Migration jobs report what actually happened rather than showing a bare success state when material was skipped, conflicting, unsupported, inactive, or deselected.

Reports include component counts, duplicates, invalid/unsupported entries, deselected items, Local DNS conflicts, failures, and a human-readable result label.

Reports are sanitized before download. Credential-named fields are removed and embedded URLs are scrubbed of user information and query strings where applicable.

## Limits

- Uploads are capped at 10 MiB.
- Text imports are capped at 200,000 lines with a clear error.
- Individual oversized lines become explicit findings instead of being accepted blindly.

## V2 note

The current public migration behavior described here belongs to the v1.1.1 release line. The clean V2 reboot is private and may use a different internal migration implementation while preserving the product requirement that migration remains preview-first, conservative, recoverable, and explicit about unsupported material.
