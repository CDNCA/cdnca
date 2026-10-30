LOCK TABLE schema_migrations, security_policies, security_policy_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_344_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 344 OR
       (SELECT max(version) FROM schema_migrations) <> 344 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=344 AND
        migration_id='344_waf_quick_block' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 344 down requires the exact verified migration head' USING ERRCODE='P3441';
    END IF;
END;
$migration_344_down$;

-- The expanded rules stay in the policies as ordinary rules (still published
-- as they are); only the switches and their idempotency records go.
DELETE FROM security_policy_write_requests WHERE operation='security_policy.quick_block';

ALTER TABLE security_policy_write_requests
    DROP CONSTRAINT security_policy_write_requests_operation_check,
    ADD CONSTRAINT security_policy_write_requests_operation_check CHECK (operation IN (
        'security_policy.create', 'security_policy.update', 'security_policy.delete'
    ));

ALTER TABLE security_policies
    DROP CONSTRAINT security_policies_quick_block_344,
    DROP COLUMN quick_block;
