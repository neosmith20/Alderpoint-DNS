# Real defect found and fixed: the V2 package build was not reproducible

Found during Gate #3 artifact recovery: the durable RC29 artifact
Dex's review depended on had been cleaned from `/tmp` after the
previous session completed. Rebuilding from the exact reviewed source
SHA (`762d26a`) to restore it surfaced a real, independent defect:
**the build itself was not reproducible**, so the original RC29 bytes
could never be exactly reconstructed even from the identical source
commit.

## What was found

Two consecutive runs of `scripts/build-v2-deb.sh` against the exact
same git `HEAD` produced two different `alderpointdns-v2_2.0.0~rc29-1_all.deb`
SHA-256 hashes. Investigated methodically rather than assumed
unfixable:

1. Extracted both `.deb`s (`dpkg-deb -R`) and diffed the trees --
   **zero content differences**. Every file's bytes were identical.
2. Checked file mtimes in the extracted trees -- **different**, by
   however many seconds apart the two builds happened to run. Root
   cause #1: `scripts/build-v2-deb.sh` stages every packaged file via
   plain `cp`, which stamps each destination file's mtime with the
   real wall-clock time of the `cp` operation, not any value derived
   from the source. `dpkg-deb --build` preserves those mtimes into the
   package's `control.tar.xz`/`data.tar.xz` members, so the compressed
   archives -- and therefore the final `.deb` -- differed even though
   the underlying file content never did.
3. Fixed by normalizing every staged file's mtime to `SOURCE_DATE_EPOCH`
   (the [reproducible-builds.org standard](https://reproducible-builds.org/specs/source-date-epoch/)),
   derived from the exact source commit being built (`git log -1
   --format=%ct HEAD`) rather than build time. Rebuilt twice more --
   **still different hashes**.
4. Extracted each ar(5) member (`control.tar.xz`/`data.tar.xz`/
   `debian-binary`) directly and hashed them independently -- this
   time **byte-identical**, confirming the inner tar archives were now
   genuinely reproducible. The remaining difference had to be in the
   outer `.deb` (`ar`) container itself. Root cause #2: `dpkg-deb
   --build` separately stamps the *outer* ar container's own per-member
   timestamp with the real build wall-clock time, independent of the
   inner tar mtimes already fixed in step 3.
5. `dpkg-deb(1)` documents native support for the same
   `SOURCE_DATE_EPOCH` convention (dpkg >= 1.18.8): *"If set, it will
   be used as the timestamp... in the deb's ar(5) container and used to
   clamp the mtime in the tar(5) file entries."* Exporting it as an
   environment variable before invoking `dpkg-deb --build` closed the
   remaining gap.

## Fix

`scripts/build-v2-deb.sh` now, immediately before `dpkg-deb --build`:

```sh
SOURCE_DATE_EPOCH="$(cd "$SOURCE_DIR" && git log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
find "$PKG" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
export SOURCE_DATE_EPOCH
```

Both the explicit `find`/`touch` (defense-in-depth, explicit intent,
though not load-bearing once `SOURCE_DATE_EPOCH` is exported since
`dpkg-deb` itself already clamps tar mtimes) and the exported
environment variable (the actual fix for the outer ar container) are
kept.

## Verification

Real, repeated, live proof -- not assumed from source review:

- Three consecutive builds of the exact same source commit now
  produce **byte-identical** `.deb` files (`sha256sum` matched all
  three times).
- Each extracted ar member (`debian-binary`, `control.tar.xz`,
  `data.tar.xz`) independently confirmed byte-identical across builds.

**Regression coverage**: `tests/v2/test_build_reproducibility.py`
(2 tests, real subprocess builds, no mocks) --
`test_two_consecutive_builds_are_byte_identical` (the same proof used
to confirm the fix) and `test_inner_ar_members_are_byte_identical`
(the finer-grained check that actually isolated root cause #2). Both
pass.

## What this means for the historical RC29 hash

The original RC29 artifact
(`0b0a06427ffec93e9949905467c23cc90d8eaca82c4552f9ceae30bc0038472c`)
was built *before* this fix, with the old non-reproducible script --
its exact bytes depended on the specific wall-clock moment that
particular build ran, information that no longer exists (the build
directory was cleaned, by design, after the prior session completed).
**That specific historical hash can never be legitimately reproduced
again**, from this source or any other -- and this document does not
claim otherwise. Per Gate #3 artifact-recovery guidance: rather than
fabricate a false match or hand back ambiguous, irreproducible bytes
under the old RC29 label, this fix is committed and a new RC30
candidate is built from the corrected, now-genuinely-reproducible
process, giving Gate #3 review exactly one unambiguous, independently
re-verifiable artifact identity going forward.
