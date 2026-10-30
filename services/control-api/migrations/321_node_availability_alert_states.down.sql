LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_321_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 321 OR
       (SELECT max(version) FROM schema_migrations) <> 321 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=321 AND
        migration_id='321_node_availability_alert_states' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 321 down requires the exact verified migration head' USING ERRCODE='P3211';
    END IF;
END;
$migration_321_down$;

-- Alert state is derived from probe reports and rebuilt on the next tick.
DROP TABLE node_availability_alert_states;
