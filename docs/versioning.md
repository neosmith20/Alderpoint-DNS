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

## History: why this repo's `VERSION` briefly read `0.4.0-beta.5` while a
## `0.4.0~beta6-1` package was dpkg-installed on the engineering host

Earlier in this development cycle, `/opt/alderpointdns` on the engineering
host was unusual: it was simultaneously (a) the private development git
repository, checked out with `VERSION = 0.4.0-beta.5` as the base for
*next-release* development, and (b) the literal `WorkingDirectory` of the
already dpkg-installed `alderpointdns` package, built from a *separately
released* source tree (the public export) with `VERSION = 0.4.0-beta.6`
and installed via `dpkg`. dpkg's package database was never told about
the subsequent git checkout, so its recorded `Version:` (`0.4.0~beta6-1`)
was stale relative to the files on disk, and the two genuinely
disagreed -- exactly the scenario `version_source_status()`'s drift
detection is designed to surface rather than silently misreport, which is
why it was left alone (not bumped to "look right" against dpkg) while
that detection/logging behavior was added.

That mismatch is also *why* the Software Updates feature (below) needed a
real fix rather than another silent workaround: a `beta.6 -> beta.5`
install genuinely looks like a downgrade under plain string/date
comparison, which is precisely the ambiguity an automatic updater must
never paper over. See the next section for the resolution.

## The development version for the Software Updates work: `0.5.0-dev.1`

`VERSION` is now `0.5.0-dev.1` (Debian package form: `0.5.0~dev1-1`),
chosen when the Software Updates feature was built, for these reasons:

- **Strictly newer than the latest published release** (`0.4.0-beta.6`)
  by ordinary SemVer precedence on the `MAJOR.MINOR.PATCH` core alone
  (`0.5.0 > 0.4.0`) -- it does not depend on any pre-release-tag string
  ordering (`dev` vs `beta`) to be "newer", so the comparison is
  unambiguous by construction, which is exactly the property an update
  engine's own test suite needs to assert against.
- **Not `1.0.0`** -- 1.0.0 is reserved for the actual stable release that
  follows this development cycle's remaining performance, documentation,
  and release-readiness passes; this branch is not that.
- **Not tagged or published anywhere** -- it exists only in this
  development branch/checkout and any disposable-VM development `.deb`
  built from it.
- **A pre-release, not a final `0.5.0`** -- `-dev.1` reuses the exact
  `-<tag>.<N>` pre-release convention `-beta.N` already established
  (see below), so if `0.5.0` is ever later released for real, dpkg
  correctly orders this development build as *older* than that release
  (`0.5.0~dev1-1 < 0.5.0-1`), not newer -- see "Generalizing the
  `-beta.N` &harr; `~betaN` substitution" below for why this matters.

## Generalizing the `-beta.N` &harr; `~betaN` substitution

`scripts/build-deb.sh` and `app/backup.py`'s `_dpkg_version_to_source_form()`
originally only rewrote the literal `-beta.N` pre-release tag. Both were
generalized to `-<tag>.<N>` &harr; `~<tag><N>` for any alphabetic tag
(`beta`, `dev`, `rc`, ...), since the Software Updates feature needed a
genuine development pre-release tag (`dev`) distinct from `beta` (which is
reserved for actual published beta releases), and any future release
process (release candidates, etc.) should not need a third bespoke
substitution added later. The leading `~` is load-bearing, not cosmetic:
Debian's version-ordering algorithm sorts `~` before everything, including
the empty string, so any `~<tag>N` form always sorts before the bare final
version it is a pre-release of -- exactly the safety property
`software_updates.py`'s "never downgrade" and "reject same version" rules
rely on when a package-install decision compares an installed pre-release
against a candidate release via `dpkg --compare-versions`.

## Recommendation for (now: use by) the Software Updates feature

- Compare using `backup.alderpointdns_app_version()` (or
  `version_source_status()["resolved"]`), not a fresh ad hoc version read
  -- it already encodes the file-primary/dpkg-fallback/git-suffix model
  above. `app/software_updates.py` does exactly this.
- Treat `version_source_status()["mismatch"] is True` as a hard stop for
  any *automatic* update decision (do not silently upgrade/compare against
  either value when they disagree) -- surface it to the administrator
  instead, exactly as the drift-detection warning already does for logs.
  `software_updates.py`'s `installed_version_status()` wraps this check
  and every update-path entry point refuses to proceed while it is true.
- Two independent comparisons are used, deliberately never conflated:
  **release/channel SemVer comparison** (`software_updates.compare_semver()`,
  used to rank GitHub releases against each other and against the
  resolved application version for channel/"is there an update"
  decisions) and **`dpkg --compare-versions`** (used only for the actual
  package-install safety gate, since that is the comparison dpkg/APT
  itself will make, and it is the one that must agree with what `apt`
  is about to do). See `docs/software-updates.md`.

## Regression tests

See `tests/test_backup.py::VersionConsistencyTest` for coverage of
`_dpkg_version_to_source_form()`, `version_source_status()`'s agree/
mismatch/no-file/no-dpkg cases (including a `-dev.N` case), and the
mismatch stderr logging (and its absence when the sources agree). See
`tests/test_software_updates.py::VersionComparisonTest` for SemVer
comparison and the explicit `0.4.0-beta.6 -> 0.5.0-dev.1`,
`0.5.0-dev.1 -> 1.0.0`, `1.0.0 -> 1.0.1`, `1.0.1 -> 1.1.0`, and
`1.1.0 -> 1.0.1` (rejected) transition tests.
