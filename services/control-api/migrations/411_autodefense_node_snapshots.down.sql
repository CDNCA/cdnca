LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_411_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 411 OR
       (SELECT max(version) FROM schema_migrations) <> 411 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=411 AND
        migration_id='411_autodefense_node_snapshots' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 411 down requires the exact verified migration head' USING ERRCODE='P4111';
    END IF;
END;
$migration_411_down$;

-- Delivery state only. Revisions are max(previous + 1, Unix milliseconds),
-- so after down and up again the next revision is still above what nodes
-- hold and nothing is refused as stale.
DROP TABLE autodefense_node_snapshots;
