-- General Settings > Appliance Identity's display name: a real,
-- live-editable override on top of appliance.yaml's own boot-time
-- Appliance.Name (see internal/appliancesettings' own doc comment).
-- NULL display_name means "no override -- use the config file value",
-- not an empty appliance name.
CREATE TABLE appliance_settings (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    display_name TEXT
);
INSERT INTO appliance_settings (id, display_name) VALUES (1, NULL);
