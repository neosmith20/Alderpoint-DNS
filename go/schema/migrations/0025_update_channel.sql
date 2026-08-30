-- 0025_update_channel: real update-channel config + last-check state --
-- closes blocker 3's real gap (V1.1.1's system_software_updates.html
-- had update channel/latest-version-check/last-checked-status; this Go
-- control plane previously had no remote feed at all, correctly
-- disclosed rather than faked). Repo/owner are real GitHub Releases
-- coordinates (owner-confirmed), not invented.
CREATE TABLE update_channel_settings (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    repo_owner            TEXT NOT NULL DEFAULT '',
    repo_name             TEXT NOT NULL DEFAULT '',
    -- token: optional (public repo works with no token, rate-limited);
    -- stored as given, same trust boundary as every other owner-
    -- supplied API credential already in control.db (blocklist source
    -- auth, replication tokens) -- this table is not the secrets-store
    -- boundary (internal/secretstore) since it never needs the
    -- root-owned agent to use it, matching internal/blocklists' own
    -- per-source-auth precedent.
    token                 TEXT NOT NULL DEFAULT '',
    last_checked_at       TEXT NOT NULL DEFAULT '',
    last_check_status     TEXT NOT NULL DEFAULT '',  -- '' | 'ok' | 'error'
    last_check_error      TEXT NOT NULL DEFAULT '',
    latest_version         TEXT NOT NULL DEFAULT '',
    latest_deb_url         TEXT NOT NULL DEFAULT '',
    latest_sha256sums_url  TEXT NOT NULL DEFAULT '',
    latest_deb_asset_name  TEXT NOT NULL DEFAULT ''
);
INSERT INTO update_channel_settings (id, repo_owner, repo_name) VALUES (1, 'neosmith20', 'Alderpoint-DNS');
