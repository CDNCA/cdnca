LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_316_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 316 OR
       (SELECT max(version) FROM schema_migrations) <> 316 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=316 AND
        migration_id='316_l4_toa' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 316 down requires the exact verified migration head' USING ERRCODE='P3161';
    END IF;
    -- A TOA stream or its history cannot be expressed before 316.
    -- Responses always carry toa; only true blocks.
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE toa) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'toa') OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE
           response_body->'toa' = 'true'::jsonb OR
           response_body#>'{publish_intent,runtime_spec}' ? 'toa' OR
           response_body->'runtime_spec' ? 'toa') THEN
        RAISE EXCEPTION 'retain L4 TOA streams and history during binary rollback' USING ERRCODE='P3162';
    END IF;
END;
$migration_316_down$;

ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_316,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_300
    CHECK(validate_l4_runtime_spec_300(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_316(uuid,uuid,uuid,jsonb);
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_toa_316, DROP COLUMN toa;
