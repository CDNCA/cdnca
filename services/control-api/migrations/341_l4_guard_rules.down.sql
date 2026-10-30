LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_341_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 341 OR
       (SELECT max(version) FROM schema_migrations) <> 341 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=341 AND
        migration_id='341_l4_guard_rules' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 341 down requires the exact verified migration head' USING ERRCODE='P3411';
    END IF;
    -- Guard rules or their history cannot be expressed before 341.
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE guard_rules IS NOT NULL) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'guard_rules') OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE response_body::text LIKE '%"guard_rules": [{%') THEN
        RAISE EXCEPTION 'retain L4 guard rules and history during binary rollback' USING ERRCODE='P3412';
    END IF;
END;
$migration_341_down$;

ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_341,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_334
    CHECK(validate_l4_runtime_spec_334(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_341(uuid,uuid,uuid,jsonb);
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_guard_rules_341, DROP COLUMN guard_rules;
DROP FUNCTION valid_l4_guard_rules_341(jsonb);
