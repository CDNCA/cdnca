LOCK TABLE schema_migrations, autodefense_node_snapshots IN ACCESS EXCLUSIVE MODE;

DO $migration_591_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 591 OR
       (SELECT max(version) FROM schema_migrations) <> 591 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=591 AND
        migration_id='591_autodefense_publish_count' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 591 down requires the exact verified migration head' USING ERRCODE='P5911';
    END IF;
END;
$migration_591_down$;

-- Only the release dialog reads it; the count starts again after a reapply.
ALTER TABLE autodefense_node_snapshots DROP COLUMN publish_count;
