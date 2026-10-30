LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_277_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 276 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 276 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=276 AND
        migration_id='276_certificate_asset_owner' AND
        checksum_sha256='300294799eb72125955b03c7fbabb35f67c6913aa776bb4a134ab4545c33c1df' AND
        down_checksum_sha256='3151ec744c3457f8d65c5b76fc3713b6d0b4f3243a7f848831bec872269c39eb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 277 requires the exact verified 276 release head' USING ERRCODE='P2770';
    END IF;
END;
$migration_277_up$;

-- No backfill: enrollment capabilities are not authenticated Connect facts.
CREATE TABLE node_session_capabilities (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    certificate_id uuid NOT NULL,
    certificate_sha256 bytea NOT NULL CHECK (octet_length(certificate_sha256)=32),
    artifact_key_id text NOT NULL REFERENCES node_artifact_encryption_keys(id) ON DELETE RESTRICT,
    selected_protocol_major integer NOT NULL CHECK (selected_protocol_major BETWEEN 1 AND 65535),
    selected_protocol_minor integer NOT NULL CHECK (selected_protocol_minor BETWEEN 0 AND 65535),
    capabilities_snapshot bytea NOT NULL CHECK (octet_length(capabilities_snapshot) BETWEEN 1 AND 65536),
    capabilities_sha256 bytea NOT NULL CHECK (octet_length(capabilities_sha256)=32),
    facts_snapshot bytea NOT NULL CHECK (octet_length(facts_snapshot) BETWEEN 1 AND 131072),
    facts_sha256 bytea NOT NULL CHECK (octet_length(facts_sha256)=32),
    gateway_workload_identity text NOT NULL CHECK (char_length(gateway_workload_identity) BETWEEN 1 AND 256),
    gateway_instance_id text NOT NULL CHECK (char_length(gateway_instance_id) BETWEEN 1 AND 128),
    registered_at timestamptz NOT NULL,
    PRIMARY KEY(node_id,session_epoch),
    FOREIGN KEY(certificate_id,node_id) REFERENCES node_certificates(id,node_id) ON DELETE RESTRICT
);

CREATE FUNCTION protect_node_session_capabilities_277() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'node session capabilities are immutable' USING ERRCODE='P2771';
END;
$$;
CREATE TRIGGER node_session_capabilities_immutable_277 BEFORE UPDATE OR DELETE ON node_session_capabilities
FOR EACH ROW EXECUTE FUNCTION protect_node_session_capabilities_277();
CREATE TRIGGER node_session_capabilities_no_truncate_277 BEFORE TRUNCATE ON node_session_capabilities
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_session_capabilities_277();
REVOKE ALL ON FUNCTION protect_node_session_capabilities_277() FROM PUBLIC,cdnca_control_app;
REVOKE ALL ON node_session_capabilities FROM PUBLIC,cdnca_control_app;
GRANT SELECT,INSERT ON node_session_capabilities TO cdnca_control_app;
