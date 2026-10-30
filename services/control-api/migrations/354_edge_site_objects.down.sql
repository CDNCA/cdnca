LOCK TABLE schema_migrations, config_versions IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_activation_node_artifacts_333 IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE edge_publication_compile_inputs IN ACCESS EXCLUSIVE MODE;

DO $migration_354_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 354 OR
       (SELECT max(version) FROM schema_migrations) <> 354 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=354 AND
        migration_id='354_edge_site_objects' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 354 down requires the exact verified migration head' USING ERRCODE='P3543';
    END IF;
    -- Site object publications, their key envelopes and snapshots above
    -- 4 MiB cannot be expressed before 354.
    IF EXISTS (SELECT 1 FROM edge_site_object_keys) OR
       EXISTS (SELECT 1 FROM configuration_artifacts WHERE media_type IN (
           'application/vnd.cdnca.edge-site-root+json;version=1',
           'application/vnd.cdnca.edge-site-object-key+json;version=1')) OR
       EXISTS (SELECT 1 FROM config_versions WHERE octet_length(canonical_snapshot) > 4194304) OR
       EXISTS (SELECT 1 FROM edge_publication_compile_inputs WHERE octet_length(site_runtime_v2::text) > 4194304) THEN
        RAISE EXCEPTION 'retain site object publications during binary rollback' USING ERRCODE='P3544';
    END IF;
END;
$migration_354_down$;

CREATE OR REPLACE FUNCTION validate_security_policy_activation_node_artifact_333()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM configuration_artifacts artifact
        JOIN config_versions version ON version.id=artifact.config_version_id
        WHERE artifact.id=NEW.artifact_id AND artifact.config_version_id=NEW.config_version_id
          AND version.configuration_scope_id=NEW.tenant_scope_id
          AND artifact.kind='configuration'
          AND artifact.encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'
          AND artifact.recipient_key_id=NEW.recipient_key_id
          AND artifact.sha256=NEW.artifact_sha256 AND artifact.sha256=sha256(artifact.wire_bytes)
    ) THEN
        RAISE EXCEPTION 'invalid security activation node artifact' USING ERRCODE='P3332';
    END IF;
    RETURN NEW;
END;
$$;

DROP TABLE edge_site_object_publications;
DROP TABLE edge_site_objects;
DROP TABLE edge_site_object_keys;
DROP FUNCTION protect_edge_site_objects_354();
ALTER TABLE edge_publication_compile_inputs DROP CONSTRAINT edge_publication_compile_inputs_v2_size_354,
    ADD CONSTRAINT edge_publication_compile_inputs_site_runtime_v2_check CHECK (site_runtime_v2 IS NULL OR
        jsonb_typeof(site_runtime_v2) = 'object' AND octet_length(site_runtime_v2::text) <= 4194304);
ALTER TABLE config_versions DROP CONSTRAINT config_versions_canonical_snapshot_354,
    ADD CONSTRAINT config_versions_canonical_snapshot_check
    CHECK (octet_length(canonical_snapshot) BETWEEN 1 AND 4194304);
