-- 0011_strong_clientid: Strong ClientID support for Managed Clients.
-- client_identifiers already supports multiple kind='clientid' rows per
-- client (UNIQUE(kind,value) from 0004_clients.sql) -- this migration
-- adds the metadata Strong ClientID needs: a human label and a revoke
-- timestamp (revoke sets this, never a row delete, so a revoked
-- identity's history survives; DeleteIdentifier in internal/clients is
-- the separate, explicit hard-delete path).
ALTER TABLE client_identifiers ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE client_identifiers ADD COLUMN revoked_at TEXT NULL;

-- Per-client explicit domain overrides -- deliberately narrower than a
-- full per-client policy-layer resolver (see internal/policy's own
-- disclosed gap): literal-domain block/allow tied to one client's
-- identity, compiled with explicit deny > explicit allow > default
-- precedence (internal/dnscompile), proving real per-identity
-- enforcement without reimplementing the whole policy engine.
CREATE TABLE client_domain_overrides (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    override_type TEXT NOT NULL CHECK(override_type IN ('block','allow')),
    pattern       TEXT NOT NULL,
    created_at    TEXT NOT NULL
);

CREATE INDEX idx_client_domain_overrides_client ON client_domain_overrides(client_id);
