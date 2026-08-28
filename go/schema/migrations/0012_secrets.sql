-- 0012_secrets: native Go secrets storage. This table holds ONLY
-- authenticated-encrypted ciphertext and non-sensitive metadata -- the
-- key that decrypts it never lives in this database, and never lives
-- in this (the unprivileged web) process at all. See
-- internal/secretstore's doc comment for the full design: the master
-- key is generated and held only by apdns-hostagent (root, outside
-- this container), and every use of a stored secret goes through a
-- narrow, named hostagent operation that decrypts internally and
-- performs one specific bounded action -- never a generic decrypt
-- endpoint.
--
-- kind + owner_ref together identify what a secret is FOR (e.g.
-- kind='notification_webhook', owner_ref=<provider_id>) -- this pair is
-- part of the AEAD associated data at seal time, so ciphertext copied
-- to a different kind/owner_ref/appliance can never decrypt even with
-- the correct key (see internal/secretstore.Context).
CREATE TABLE secrets (
    id          TEXT PRIMARY KEY,          -- secretstore.NewID(): random, opaque, never derived from the value
    kind        TEXT NOT NULL,             -- e.g. 'notification_webhook', 'upstream_auth', 'replication_ca_key', 'dnscrypt_identity'
    owner_ref   TEXT NOT NULL,             -- the owning record's own stable id (provider_id, endpoint id, ...)
    key_version INTEGER NOT NULL,          -- which master-key version sealed this record (see internal/hostagentd/ops_secrets.go)
    nonce       BLOB NOT NULL,             -- AEAD nonce, unique per seal
    ciphertext  BLOB NOT NULL,             -- AES-256-GCM ciphertext + auth tag; NEVER plaintext
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    revoked_at  TEXT NULL                  -- set (never deleted) when an owner replaces/revokes a secret, preserving audit history
);

CREATE INDEX idx_secrets_kind_owner ON secrets(kind, owner_ref);
