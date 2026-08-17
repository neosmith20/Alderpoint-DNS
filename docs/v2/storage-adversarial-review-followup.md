# Storage adversarial-tamper follow-up (roadmap Priority 10 continuation)

Closes the remaining STORAGE items `adversarial-security-pass.md` left
unreviewed this session ("Parquet/aggregate-DB/Tier-B corruption as a
security surface specifically... migration state tampering... secret
symlink attacks... wasn't independently re-attacked live"). Reviewed
code + existing tests rather than re-attacking live where existing
coverage already proves the property directly.

- **Corrupt Parquet segments**: already handled by design, not just
  accidentally -- `analytics_query.py`'s `_files_for_range` catches
  `SegmentValidationError` and excludes the bad segment rather than
  raising; proven by `tests/v2/test_analytics_failure_isolation.py`'s
  `test_all_segments_corrupt_query_returns_empty_not_crash` and
  `test_one_corrupt_segment_among_valid_ones_still_returns_valid_rows`.
  An attacker who can write to the Parquet directory can deny a query
  window's worth of analytics; they cannot inject fabricated rows into
  a query result or crash the query path.
- **Corrupt aggregate DB**: deliberately raises a catchable error
  rather than silently returning fabricated statistics (`test_aggregate
  _db_corrupt_file_raises_catchable_error_not_silent_bad_data`) -- the
  correct posture for a stats surface (never serve invented numbers),
  and analytics failures are already architecturally isolated from DNS
  answering (a corrupt aggregates.db can 500 the dashboard API; it
  cannot touch `dnsdist`/`named`).
- **Tier B corruption**: already covered functionally (kill-during-
  prewarm, corrupt/missing persisted state -> cold-cache fallback,
  DNS stays operational) in `docs/v2/tier-b-and-failure-domains.md`;
  not re-attacked from a specifically adversarial angle this pass, but
  the property being tested (corrupted persisted state can't stop DNS
  from answering) is the same property an adversarial tamper attempt
  would also be exercising.
- **Migration-state tampering**: `migration_state.load()` raises on a
  corrupt/truncated state file rather than silently trusting partial or
  malformed content (`test_load_corrupt_raises_not_silently_ignored`).
  The state file itself carries no cryptographic integrity check
  (no HMAC/signature) -- reviewed whether that's a real gap: the
  migration directory is created `0o750` (`_chown_best_effort`, owner+
  group only, no world access), migration is a manual root-only local
  CLI operation with no network-facing surface, so tampering with this
  specific file requires an attacker already at a privilege level
  (root, or the `alderpointdns-v2` group) where they could achieve
  equivalent or worse outcomes directly against `control.db` or the
  secret store instead. Concluded: OS-level file permissions are the
  correct, proportionate control here, matching every other local
  root-owned state file in this codebase (none of which are separately
  signed either) -- not a real gap, not fixed.
- **Secret symlink attacks**: code review only, not independently
  re-attacked live this pass -- already covered by
  `tests/v2/test_secret_store.py`'s `test_get_refuses_symlink`/
  `test_delete_refuses_symlink` (real `SecretSymlinkError` defense,
  verified by prior sessions' review per
  `docs/v2/adversarial-security-pass.md`).

No new defects found or fixed by this review.
