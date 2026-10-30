LOCK TABLE schema_migrations,node_gateway_port_transitions,node_gateway_port_transition_command_outbox,
    node_gateway_port_transition_status_events IN ACCESS EXCLUSIVE MODE;

DO $migration_180_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>180 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>180 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=180 AND migration_id='180_node_gateway_port_transitions' AND
              checksum_sha256='a3dd89eeeaa2179ececeb7556e5f242b1d1c93a088eb7a0f645fe6c15e5441a5' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 180 rollback requires the exact verified 180 head' USING ERRCODE='P1801';
    END IF;
    IF EXISTS (SELECT 1 FROM node_gateway_port_transitions) OR
       EXISTS (SELECT 1 FROM node_gateway_port_transition_command_outbox) OR
       EXISTS (SELECT 1 FROM node_gateway_port_transition_status_events) THEN
        RAISE EXCEPTION 'migration 180 rollback would discard durable gateway port transition evidence'
            USING ERRCODE='P1802';
    END IF;
END;
$migration_180_down$;

DROP TABLE node_gateway_port_transition_status_events;
DROP TABLE node_gateway_port_transition_command_outbox;
DROP TABLE node_gateway_port_transitions;
