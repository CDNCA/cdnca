LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_384_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 383 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 383 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=383 AND
        migration_id='383_account_suspension_site_holds' AND
        checksum_sha256='a2c402da2f2d338b01c61b52c985b17d2f736358275e3f05601c068402145dfd' AND
        down_checksum_sha256='986483de8f74de7950de1886f3a636c2950437921abf2e5ed2c880f5341dadc2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.admin_inbox_messages') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 384 requires the exact verified 383 release head' USING ERRCODE='P3840';
    END IF;
END;
$migration_384_up$;

-- r136 ge-account (placeholder number 384, guard on the 383 head; renumbered
-- on merge): platform administrator message center (GoEdge comparison G8,
-- missing item 6). Every platform operations event enqueued for a platform
-- member (node offline/recovered, ACME HTTP-01 epoch drift, staff ticket
-- events; notification.PlatformEventType) also lands here, whatever the
-- email/SMS switches say. Only the event type and its public template values
-- are stored; the console renders the text per language. Read messages older
-- than 180 days are pruned by the writer.
CREATE TABLE admin_inbox_messages (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    recipient_user_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9._-]{0,95}$'),
    source_event_id text NOT NULL CHECK (char_length(source_event_id) BETWEEN 1 AND 256),
    params jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 16384),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    read_at timestamptz CHECK (read_at IS NULL OR isfinite(read_at)),
    UNIQUE (recipient_user_id, event_type, source_event_id),
    FOREIGN KEY (scope_id, recipient_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE CASCADE
);
CREATE INDEX admin_inbox_messages_recipient_384_idx ON admin_inbox_messages (recipient_user_id, created_at DESC, id DESC);
CREATE INDEX admin_inbox_messages_unread_384_idx ON admin_inbox_messages (recipient_user_id) WHERE read_at IS NULL;

REVOKE ALL ON admin_inbox_messages FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_inbox_messages TO cdnca_control_app, cdnca_control_runtime;
