-- 0013_notification_secrets: move notification-provider secret material
-- (a webhook/Slack URL is itself a bearer credential, a Pushover
-- "user_key:app_token" pair, or an SMTP password -- see
-- app/notifications.py's own doc comment for why the whole value is
-- sensitive, not just one sub-field) out of this plaintext table
-- entirely, into the encrypted `secrets` table (0012). The old
-- plaintext `endpoint` column is dropped outright, not just
-- deprecated: verified against the live deployed :10443 database
-- before writing this migration -- notification_providers had zero
-- rows, so there is nothing to carry forward.
ALTER TABLE notification_providers DROP COLUMN endpoint;
ALTER TABLE notification_providers ADD COLUMN config_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE notification_providers ADD COLUMN has_secret INTEGER NOT NULL DEFAULT 0;
