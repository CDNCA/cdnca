LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_417_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 417 OR
       (SELECT max(version) FROM schema_migrations) <> 417 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=417 AND
        migration_id='417_rule_pack_mount_suspensions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 417 down requires the exact verified migration head' USING ERRCODE='P4171';
    END IF;
END;
$migration_417_down$;

-- Suspended mounts are dropped: their sites keep publishing without them
-- (re-enable and publish the pack to mount it again).
DROP TABLE rule_pack_mount_suspensions;
