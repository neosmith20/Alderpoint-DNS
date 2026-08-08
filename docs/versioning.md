# Versioning

Alderpoint DNS uses semantic versioning:

- `MAJOR`: incompatible data, configuration, or API changes.
- `MINOR`: backward-compatible features.
- `PATCH`: backward-compatible fixes.
- Pre-release labels such as `0.4.0-beta.1` identify external test builds.

The current source version is stored in `VERSION`. Release artifacts must use
the same version in Debian metadata and release notes.

## Canonical source of truth

The **`VERSION` file** at the repository/install root (`/opt/alderpointdns/VERSION`
on a package install) is Alderpoint DNS's single source of truth for the
application version. Everything else is derived from it or is a fallback
for when it is unavailable:

- **`scripts/build-deb.sh`** reads `VERSION` and derives the Debian package
  `Version:` field from it deterministically:
  `0.4.0-beta.6` &rarr; `0.4.0~beta6-1` (the `-beta.N` semver-style
  pre-release tag becomes `~betaN`, per Debian's version-ordering rules,
  with `-1` appended as the Debian revision). `app/backup.py`'s
  `_dpkg_version_to_source_form()` reverses this exact substitution so a
  dpkg-reported version can be compared against a `VERSION`-file-style
  string.
- **`app/backup.py`'s `alderpointdns_app_version()`** (used for backup
  manifests, restore previews, and anywhere else the app-facing version
  string is needed) reads `VERSION` first. If it's missing, empty, or
  fails a basic sanity check (`_VERSION_RE`), it falls back to asking
  `dpkg-query -W -f='${Version}' alderpointdns` for the installed
  package's own record. A short development-checkout suffix
  (`+git.<short-hash>`) is appended when `APP_ROOT/.git` exists and `git`
  is on `PATH` -- packaged installs are plain files, not a git clone, and
  never hit this path.
- **`packaging/debian/changelog`** carries its own, independently
  maintained Debian-style version/changelog entries (`dpkg-query`,
  `apt list --installed`, and `apt changelog` all read this). Because
  `scripts/build-deb.sh` derives the actual package `Version:` field from
  `VERSION` rather than from the changelog's top entry, keeping the
  changelog's leading version line in sync with `VERSION` at release time
  is a process discipline, not something enforced by the build.

There is currently **no user-facing "About"/status page or API endpoint**
that surfaces the resolved application version to an administrator -- the
only place it appears today is inside backup manifests and the restore
preview (`preview.manifest.alderpointdns_app_version` in
`web/templates/backup.html`). A future Software Updates feature will need
to add one; when it does, it should call
`backup.alderpointdns_app_version()` (or `version_source_status()`, below)
rather than re-deriving the version itself.

## Detecting drift between `VERSION` and dpkg

`app/backup.py`'s **`version_source_status()`** independently reads both
`VERSION` and dpkg's record, normalizes the dpkg version back to
`VERSION`-file form, and reports whether they agree:

```python
{
    "resolved": "0.4.0-beta.6",       # what alderpointdns_app_version() would report from this source
    "source": "version_file",          # "version_file" | "dpkg" | "none"
    "file_version": "0.4.0-beta.6",
    "dpkg_version": "0.4.0~beta6-1",
    "dpkg_version_normalized": "0.4.0-beta.6",
    "mismatch": False,
}
```

On a package built through the normal `scripts/build-deb.sh` pipeline and
installed via `dpkg -i`/`apt`, `VERSION` and dpkg's record are stamped
from the exact same source tree at build time and **always agree** --
`mismatch` should never be `True` in production. `alderpointdns_app_version()`
consults dpkg (whenever a `VERSION` file is present) purely to run this
check, and logs a syslog-priority warning to stderr
(`<4>alderpointdns: VERSION file (...) does not match the dpkg-installed
package version (...)`) if it ever finds a disagreement, without changing
which value is reported (the file still wins -- see below for why).

## Why the file wins on a genuine mismatch

Two ways to resolve a disagreement were considered:

1. **Prefer dpkg's record.** It's the package manager's ground truth for
   "what's installed" and can't be hand-edited by mistake -- but this
   project's own tooling never edits `VERSION` outside of a package
   rebuild, so dpkg only diverges from the file if something modified the
   on-disk files after install *outside* of dpkg.
2. **Prefer the `VERSION` file.** It's what `create_backup()` and any
   other in-process caller are actually running *right now*, on this
   exact checkout of the code -- which is what the app version is meant
   to describe. If a manifest reported a dpkg version because that's what
   the package database says, but the actual code on disk is a
   further-modified dev checkout (exactly this branch's situation, or a
   hotfix applied by hand), the manifest would misrepresent what
   produced the backup.

The file wins, matching the module's original design intent (`VERSION` is
"the preferred source" -- see `_read_version_file()`'s docstring) --
because the value being described is "what code generated this backup /
is running right now," and only the file can attest to that. dpkg remains
a legitimate fallback for corrupted/missing `VERSION`, and the drift
detection above ensures a real mismatch is never silently invisible.

## Why this repo's `VERSION` currently reads `0.4.0-beta.5` while a
## `0.4.0~beta6-1` package is dpkg-installed on this engineering host

`/opt/alderpointdns` on this particular engineering host is unusual: it is
simultaneously (a) the private development git repository being edited
in this session, checked out with `VERSION = 0.4.0-beta.5` as the base
for *next-release* development, and (b) the literal `WorkingDirectory` of
the already dpkg-installed `alderpointdns` package, which was built from
a *separately released* source tree (the public export) with
`VERSION = 0.4.0-beta.6` and installed via `dpkg`. dpkg's package
database was never told about the subsequent git checkout -- dpkg has no
way to know files under a path it manages were changed outside of `dpkg
-i`/`apt` -- so its recorded `Version:` (`0.4.0~beta6-1`) is now stale
relative to the actual files on disk, and the two genuinely disagree.
This is a property of how this specific engineering sandbox is laid out
(a git working tree and a package's live install directory happen to be
the same path), not a defect in the versioning model itself: a normal
production host never has its dpkg-managed files hand-edited outside of a
package operation, so this situation cannot arise there. It's exactly the
scenario `version_source_status()`'s drift detection above is designed to
surface rather than silently misreport, and this document is that
surfacing.

Per this task's explicit instruction, `VERSION` was **not** bumped to
"look right" against dpkg -- only the detection/logging behavior above was
added, and `VERSION` remains an accurate description of what commit this
checkout's next-release development is built on top of.

## Recommendation for the future Software Updates feature

- Compare using `backup.alderpointdns_app_version()` (or
  `version_source_status()["resolved"]`), not a fresh ad hoc version read
  -- it already encodes the file-primary/dpkg-fallback/git-suffix model
  above.
- Treat `version_source_status()["mismatch"] is True` as a hard stop for
  any *automatic* update decision (do not silently upgrade/compare against
  either value when they disagree) -- surface it to the administrator
  instead, exactly as the drift-detection warning already does for logs.
- When normal semantic versions (`1.0.0`, `1.0.1`, `1.1.0`, ...) are
  adopted after this development cycle, `scripts/build-deb.sh`'s
  `-beta.N` &harr; `~betaN` substitution becomes a no-op (no `-beta.N`
  suffix to rewrite) and `_dpkg_version_to_source_form()` continues to
  work unchanged -- ordinary semver strings round-trip through the
  existing Debian-revision-stripping step with no further changes needed.

## Regression tests

See `tests/test_backup.py::VersionConsistencyTest` for coverage of
`_dpkg_version_to_source_form()`, `version_source_status()`'s agree/
mismatch/no-file/no-dpkg cases, and the mismatch stderr logging (and its
absence when the sources agree).
