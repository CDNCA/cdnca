LOCK TABLE schema_migrations, l4_forwards, l4_forward_listeners, l4_publish_intents, l4_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_293_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 293 OR
       (SELECT max(version) FROM schema_migrations) <> 293 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=293 AND
        migration_id='293_l4_tls_passthrough' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 293 down requires the exact verified migration head' USING ERRCODE='P2932';
    END IF;
    -- Passthrough streams and their history cannot be expressed before 293,
    -- and sockets shared by SNI would break the exclusive indexes.
    -- Responses always carry tls_passthrough; only true values block.
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE tls_passthrough) OR
       EXISTS (SELECT 1 FROM l4_publish_intents WHERE runtime_spec ? 'tls_passthrough') OR
       EXISTS (SELECT 1 FROM l4_write_requests WHERE response_body->'tls_passthrough'='true'::jsonb OR
           response_body#>'{publish_intent,runtime_spec}' ? 'tls_passthrough' OR
           response_body->'runtime_spec' ? 'tls_passthrough') THEN
        RAISE EXCEPTION 'retain TLS passthrough streams and history during binary rollback' USING ERRCODE='P2933';
    END IF;
END;
$migration_293_down$;

DROP TRIGGER l4_forwards_293_passthrough_facts ON l4_forwards;
DROP TRIGGER l4_publish_intents_293_passthrough_facts ON l4_publish_intents;
DROP FUNCTION check_l4_passthrough_facts_293();
ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_293,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_248
    CHECK(validate_l4_runtime_spec_248(stream_id,scope_id,site_id,runtime_spec));
DROP FUNCTION validate_l4_runtime_spec_293(uuid,uuid,uuid,jsonb);

DROP TRIGGER l4_listener_293_server_names ON l4_forward_listeners;
DROP FUNCTION sync_l4_server_names_293();
DROP TABLE l4_forward_server_names;

DROP TRIGGER l4_forwards_293_primary_listener ON l4_forwards;
CREATE TRIGGER l4_forwards_248_primary_listener AFTER INSERT OR UPDATE ON l4_forwards
FOR EACH ROW EXECUTE FUNCTION sync_l4_primary_listener_248();
DROP FUNCTION sync_l4_primary_listener_293();
DROP TRIGGER l4_listener_293_guard ON l4_forward_listeners;
CREATE TRIGGER l4_listener_248_guard BEFORE INSERT OR UPDATE OR DELETE ON l4_forward_listeners
FOR EACH ROW EXECUTE FUNCTION protect_l4_listener_248();
DROP FUNCTION protect_l4_listener_293();

DROP INDEX l4_forward_listeners_socket_293_idx;
CREATE UNIQUE INDEX l4_forward_listeners_socket_248_idx ON l4_forward_listeners(protocol, port) WHERE reserved;
DROP INDEX l4_forwards_protocol_port_active_293_idx;
CREATE UNIQUE INDEX l4_forwards_protocol_port_active_idx ON l4_forwards(protocol, listen_port) WHERE deleted_at IS NULL;

ALTER TABLE l4_forward_listeners DROP CONSTRAINT l4_forward_listeners_tls_passthrough_293,
    DROP COLUMN server_names, DROP COLUMN tls_passthrough;
ALTER TABLE l4_forwards DROP CONSTRAINT l4_forwards_tls_passthrough_293,
    DROP COLUMN server_names, DROP COLUMN tls_passthrough;
DROP FUNCTION valid_l4_server_names_293(text[]);
