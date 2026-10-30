LOCK TABLE node_gateway_port_transition_status_events IN ACCESS EXCLUSIVE MODE;

-- Historical rows do not contain the original protobuf payload and must stay unknown.
ALTER TABLE node_gateway_port_transition_status_events
    ADD COLUMN payload_sha256 bytea,
    ADD CONSTRAINT node_port_transition_status_payload_256
        CHECK (payload_sha256 IS NULL OR octet_length(payload_sha256)=32);
