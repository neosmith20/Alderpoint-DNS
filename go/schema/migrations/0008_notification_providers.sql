-- 0008_notification_providers: native Go schema for the Notifications
-- page, matching app/v2/notification_store.py's notification_providers
-- table field-for-field for the metadata columns -- see
-- internal/notifications's doc comment for why secret_ref is
-- deliberately not carried over (no Go-native secrets store exists yet).
CREATE TABLE notification_providers (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id  TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL CHECK(kind IN ('webhook','email_smtp','pushover','slack')),
    display_name TEXT NOT NULL,
    endpoint     TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
