LOCK TABLE schema_migrations, security_activation_capability_waits IN ACCESS EXCLUSIVE MODE;

DO $migration_478_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 478 OR
       (SELECT max(version) FROM schema_migrations) <> 478 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=478 AND
        migration_id='478_security_activation_rule_pack_waits' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 478 down requires the exact verified migration head' USING ERRCODE='P4781';
    END IF;
    -- 477 cannot hold a rule pack wait: refuse rather than drop the requests.
    IF EXISTS (SELECT 1 FROM security_activation_capability_waits WHERE wait_kind = 'rule_pack') THEN
        RAISE EXCEPTION 'migration 478 down refuses to drop recorded rule pack waits' USING ERRCODE='P4782';
    END IF;
END;
$migration_478_down$;

ALTER TABLE security_activation_capability_waits
    DROP CONSTRAINT security_activation_capability_waits_kind_478_check,
    ALTER COLUMN capability SET NOT NULL,
    ALTER COLUMN required_api_version SET NOT NULL,
    DROP COLUMN rule_pack_sha256,
    DROP COLUMN wait_kind;
