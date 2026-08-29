-- 0017_dnscrypt_identity: real DNSCrypt provider/resolver key material
-- provisioning (internal/dnscryptprovision), closing the disclosed gap
-- in 0007_dns_transports.sql -- DNSCrypt here was enable/port/
-- provider_name only, honestly reported as never provisioned. Mirrors
-- app/v2/dnscrypt_provisioning.py's real dnsdist-generated key material,
-- stored as real files on disk (provider_key_path/cert_path/key_path,
-- the same "a real file path, not a DB blob" convention
-- internal/tlscert already uses for the management TLS cert/key dnsdist
-- itself also reuses) plus the small amount of genuinely non-sensitive
-- metadata (the public key, safe to disclose -- it IS the fingerprint
-- clients pin; the signed certificate bytes, which any DNSCrypt client
-- fetches unauthenticated by design).
ALTER TABLE dnscrypt_settings ADD COLUMN provider_public_key_b64 TEXT NOT NULL DEFAULT '';
ALTER TABLE dnscrypt_settings ADD COLUMN provider_key_path TEXT NOT NULL DEFAULT '';
ALTER TABLE dnscrypt_settings ADD COLUMN cert_path TEXT NOT NULL DEFAULT '';
ALTER TABLE dnscrypt_settings ADD COLUMN key_path TEXT NOT NULL DEFAULT '';
ALTER TABLE dnscrypt_settings ADD COLUMN cert_serial INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dnscrypt_settings ADD COLUMN cert_valid_from INTEGER NOT NULL DEFAULT 0;
ALTER TABLE dnscrypt_settings ADD COLUMN cert_valid_until INTEGER NOT NULL DEFAULT 0;
