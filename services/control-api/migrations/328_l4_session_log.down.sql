LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_328_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 328 OR
       (SELECT max(version) FROM schema_migrations) <> 328 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=328 AND
        migration_id='328_l4_session_log' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 328 down requires the exact verified migration head' USING ERRCODE='P3281';
    END IF;
    -- A logging stream or its history cannot be expressed before 328.
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE session_log_enabled) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'session_log') OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE
           COALESCE(response_body->>'session_log_enabled','false')<>'false' OR
           response_body#>'{publish_intent,runtime_spec}' ? 'session_log' OR
           response_body->'runtime_spec' ? 'session_log') THEN
        RAISE EXCEPTION 'retain L4 session logs and history during binary rollback' USING ERRCODE='P3282';
    END IF;
END;
$migration_328_down$;

ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_328,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_316
    CHECK(validate_l4_runtime_spec_316(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_328(uuid,uuid,uuid,jsonb);
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_session_log_328, DROP COLUMN session_log_enabled;
