-- 0028_dnsdist_api_key: persists the dnsdist webserver REST API key
-- this control plane uses to poll per-backend upstream-resolver
-- telemetry (internal/dnsruntime.Orchestrator's own DnsdistAPIKey --
-- see internal/hostagentd/ops_dnsruntime_upstreamstats.go's doc
-- comment for the real dnsdist endpoint this authenticates against).
--
-- Real defect this fixes: the key was previously generated fresh on
-- every web-process start and never persisted, "safe" in the sense
-- that every real promote() call re-sends the current key alongside
-- the compiled config it's part of -- but dnsdist itself is NOT
-- restarted just because the web process was (a routine redeploy,
-- crash-restart, or host reboot never touches dnsdist), so the
-- currently-running dnsdist keeps answering to whatever OLDER key was
-- compiled into it at its own last promote. Every poll from the new
-- process's freshly-generated key then fails authentication (a real
-- HTTP 401 against dnsdist's own API) until some UNRELATED config
-- change happens to trigger a fresh promote -- in practice, an owner
-- who rarely touches DNS Settings after initial setup could see "Top
-- Upstream Resolvers" stay empty indefinitely after every restart,
-- with no obvious cause and no visible way to fix it. Persisting the
-- key here means it survives a web-process restart intact, so it
-- keeps matching whatever dnsdist is already running with no gap at
-- all in the common case (dnsdist itself hasn't restarted either).
-- This API is loopback-only (127.0.0.1:<port>, never exposed off-box),
-- so a long-lived key carries none of the exposure a public credential
-- would.
CREATE TABLE dnsdist_api_key (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    key_value  TEXT NOT NULL,
    created_at TEXT NOT NULL
);
