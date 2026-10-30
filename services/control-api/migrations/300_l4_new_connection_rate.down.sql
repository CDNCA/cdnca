LOCK TABLE schema_migrations, l4_forwards, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_300_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 300 OR
       (SELECT max(version) FROM schema_migrations) <> 300 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=300 AND
        migration_id='300_l4_new_connection_rate' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 300 down requires the exact verified migration head' USING ERRCODE='P3001';
    END IF;
    -- A limited stream or its history cannot be expressed before 300.
    -- Responses always carry the rate; only non-zero values block.
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE max_new_connections_per_client_per_second > 0) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'new_conn_rate') OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE
           COALESCE(response_body->>'max_new_connections_per_client_per_second','0')<>'0' OR
           response_body#>'{publish_intent,runtime_spec}' ? 'new_conn_rate' OR
           response_body->'runtime_spec' ? 'new_conn_rate') THEN
        RAISE EXCEPTION 'retain L4 new connection rates and history during binary rollback' USING ERRCODE='P3002';
    END IF;
END;
$migration_300_down$;

ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_300,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_293
    CHECK(validate_l4_runtime_spec_293(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_300(uuid,uuid,uuid,jsonb);
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_new_connection_rate_300,
    DROP COLUMN new_connection_ban_seconds, DROP COLUMN new_connection_burst,
    DROP COLUMN max_new_connections_per_client_per_second;
