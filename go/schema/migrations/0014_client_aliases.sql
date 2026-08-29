-- 0014_client_aliases: Client Aliases (V1.1.1's local_dns.py
-- upsert_alias/delete_alias/alias_for_client, read directly) -- a
-- CIDR-to-display-name mapping so an address that isn't (or isn't yet)
-- a Strong managed client still gets a real, human label wherever a
-- client address is shown (Dashboard/Query Log/Client analytics),
-- instead of always falling back to the raw IP. Deliberately narrower
-- than V1.1.1's real BIND-authoritative-zone Local DNS architecture --
-- this is metadata/display only, not a DNS-answering record.
CREATE TABLE client_aliases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
