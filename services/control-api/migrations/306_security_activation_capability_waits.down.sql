LOCK TABLE schema_migrations, security_activation_capability_waits IN ACCESS EXCLUSIVE MODE;

DO $migration_306_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 306 OR
       (SELECT max(version) FROM schema_migrations) <> 306 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=306 AND
        migration_id='306_security_activation_capability_waits' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 306 down requires the exact verified migration head' USING ERRCODE='P3061';
    END IF;
END;
$migration_306_down$;

-- Waiting activations are dropped: their operators publish again by hand.
DROP TABLE security_activation_capability_waits;
