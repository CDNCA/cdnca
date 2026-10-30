LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_271_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 270 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 270 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=270 AND
        migration_id='270_l2_topology_default_region' AND
        checksum_sha256='1cd3686aa0036c42db838ce17741f9e15f5ca3c9b3333a520a4807176d4e4b27' AND
        down_checksum_sha256='22c1da06ca8843990f6c98d8384c7fa88d710a18b9e2d461070f95eea993bb4b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
           migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
           checksum_sha256 IS NULL OR down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL) THEN
        RAISE EXCEPTION 'migration 271 requires the exact verified 270 release head' USING ERRCODE='P2710';
    END IF;
END;
$migration_271_up$;

CREATE TABLE node_network_inventory_reports (
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    request_id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id),
    scope_id uuid NOT NULL REFERENCES access_scopes(id),
    certificate_id uuid NOT NULL REFERENCES node_certificates(id),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    peer_ip inet,
    inventory_json jsonb NOT NULL CHECK (jsonb_typeof(inventory_json)='object'),
    ipv4_state text NOT NULL CHECK (ipv4_state IN ('verified','address_conflict','peer_mismatch','no_default_route','no_global_address','ambiguous_route','unavailable')),
    ipv6_state text NOT NULL CHECK (ipv6_state IN ('verified','address_conflict','peer_mismatch','no_default_route','no_global_address','ambiguous_route','unavailable')),
    received_at timestamptz NOT NULL
);
CREATE INDEX node_network_inventory_latest_271 ON node_network_inventory_reports(node_id,sequence DESC);

CREATE FUNCTION protect_node_network_inventory_271() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'node network inventory reports are append-only' USING ERRCODE='P2713';
END;
$$;
CREATE TRIGGER node_network_inventory_immutable_271
BEFORE UPDATE OR DELETE OR TRUNCATE ON node_network_inventory_reports
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_network_inventory_271();

CREATE VIEW node_network_inventory_latest AS
SELECT DISTINCT ON (node_id) node_id,scope_id,ipv4_state,ipv6_state,received_at,
    inventory_json->'ipv4'->>'address' AS ipv4_address,
    inventory_json->'ipv6'->>'address' AS ipv6_address
FROM node_network_inventory_reports ORDER BY node_id,sequence DESC;
REVOKE ALL ON node_network_inventory_reports,node_network_inventory_latest FROM PUBLIC;
DO $migration_271_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT ON node_network_inventory_reports TO cdnca_control_app;
        GRANT SELECT ON node_network_inventory_latest TO cdnca_control_app;
        GRANT USAGE ON SEQUENCE node_network_inventory_reports_sequence_seq TO cdnca_control_app;
    END IF;
END;
$migration_271_grants$;
