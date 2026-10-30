LOCK TABLE node_gateway_port_transition_status_events IN ACCESS EXCLUSIVE MODE;

DO $migration_256_down$
BEGIN
    IF EXISTS (SELECT 1 FROM node_gateway_port_transition_status_events WHERE payload_sha256 IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 256 rollback would erase status receipt identity; keep the schema and deploy a compatible binary'
            USING ERRCODE='P2561';
    END IF;
END;
$migration_256_down$;

ALTER TABLE node_gateway_port_transition_status_events
    DROP CONSTRAINT node_port_transition_status_payload_256,
    DROP COLUMN payload_sha256;
