LOCK TABLE schema_migrations, security_custom_rule_report_state IN ACCESS EXCLUSIVE MODE;

DO $migration_283_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 283 OR
       (SELECT max(version) FROM schema_migrations) <> 283 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=283 AND
        migration_id='283_security_custom_rule_report_state' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 283 down requires the exact verified migration head' USING ERRCODE='P2830';
    END IF;
END;
$migration_283_down$;

-- Sender state only: the next run rebuilds the snapshot from the live tables
-- and re-uploads it under a fresh sequence.
DROP TABLE security_custom_rule_report_state;
