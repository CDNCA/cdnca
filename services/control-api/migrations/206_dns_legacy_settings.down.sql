LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_206_down$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=206
          AND migration_id='206_dns_legacy_settings'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 206 rollback requires a verified 206 DNS legacy settings head' USING ERRCODE='P2061';
    END IF;
END;
$migration_206_down$;

REVOKE SELECT, INSERT, UPDATE, DELETE
    ON TABLE dns_legacy_settings, dns_legacy_settings_write_requests
    FROM cdnca_control_app;
DROP TABLE dns_legacy_settings_write_requests;
DROP TABLE dns_legacy_settings;
