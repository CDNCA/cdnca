LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_408_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 408 OR
       (SELECT max(version) FROM schema_migrations) <> 408 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=408 AND
        migration_id='408_security_ban_list' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 408 down requires the exact verified migration head' USING ERRCODE='P4081';
    END IF;
    -- The ban list is audited security history (manual bans, releases):
    -- rolling back would lose who banned or released whom.
    IF EXISTS (SELECT 1 FROM security_ban_entries) THEN
        RAISE EXCEPTION 'migration 408 rollback would discard the security ban list' USING ERRCODE='P4082';
    END IF;
END;
$migration_408_down$;

DROP TABLE security_ban_node_state;
DROP TABLE security_ban_sync_cursor;
DROP TABLE security_ban_write_requests;
DROP TABLE security_ban_entries;
