-- 0004_clients: native Go schema for Clients (managed clients + groups),
-- matching app/v2/control_db.py's clients/client_identifiers/
-- client_groups/client_group_members tables field-for-field. Deliberately
-- NOT included here (see internal/clients's doc comment): the policy-layer
-- tables (global/network/group/client policy assignment) and the
-- observed-clients/discovery tables -- both separate, larger pieces.
CREATE TABLE client_groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL UNIQUE,
    priority   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE client_identifiers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id  INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK(kind IN ('ipv4','ipv4_cidr','ipv6','ipv6_cidr','clientid')),
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(kind, value)
);

CREATE TABLE client_group_members (
    group_id  INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    PRIMARY KEY(group_id, client_id)
);

CREATE INDEX idx_client_identifiers_client ON client_identifiers(client_id);
CREATE INDEX idx_client_group_members_client ON client_group_members(client_id);
