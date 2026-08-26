-- 0007_dns_transports: native Go schema for the Encryption page's DNS
-- Transport settings (DoT/DoH/DoQ/DoH3 + DNSCrypt enable/port), matching
-- app/v2/policy_store.py's dns_transport_settings + dnscrypt_settings
-- tables field-for-field for the parts internal/dnstransports actually
-- stores. Deliberately narrower than Python's dnscrypt_settings: no
-- cert/identity columns here (those need a Go-native secrets store,
-- which doesn't exist yet -- see internal/dnstransports's doc comment).
CREATE TABLE dns_transport_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    dot_enabled  INTEGER NOT NULL DEFAULT 0,
    dot_port     INTEGER NOT NULL DEFAULT 853,
    doh_enabled  INTEGER NOT NULL DEFAULT 0,
    doh_port     INTEGER NOT NULL DEFAULT 443,
    doh_path     TEXT NOT NULL DEFAULT '/dns-query',
    doq_enabled  INTEGER NOT NULL DEFAULT 0,
    doq_port     INTEGER NOT NULL DEFAULT 853,
    doh3_enabled INTEGER NOT NULL DEFAULT 0,
    doh3_port    INTEGER NOT NULL DEFAULT 443,
    updated_at   TEXT NOT NULL
);

CREATE TABLE dnscrypt_settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    enabled       INTEGER NOT NULL DEFAULT 0,
    port          INTEGER NOT NULL DEFAULT 5443,
    provider_name TEXT NOT NULL DEFAULT '2.dnscrypt-cert.alderpointdns-go.local',
    updated_at    TEXT NOT NULL
);
