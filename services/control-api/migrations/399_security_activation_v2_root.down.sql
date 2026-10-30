LOCK TABLE schema_migrations, security_policy_activation_node_artifacts_333 IN ACCESS EXCLUSIVE MODE;

DO $migration_399_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 399 OR
       (SELECT max(version) FROM schema_migrations) <> 399 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=399 AND
        migration_id='399_security_activation_v2_root' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 399 down requires the exact verified migration head' USING ERRCODE='P3991';
    END IF;
END;
$migration_399_down$;

-- Back to the 354 trigger: only the v1 root. Rows already recorded stay
-- (the trigger checks inserts only).
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
          AND artifact.sha256=sha256(artifact.wire_bytes) AND (
            (artifact.media_type<>'application/vnd.cdnca.edge-site-object-key+json;version=1' AND
             artifact.sha256=NEW.artifact_sha256) OR
            (artifact.media_type='application/vnd.cdnca.edge-site-object-key+json;version=1' AND EXISTS (
                SELECT 1 FROM configuration_artifacts root
                WHERE root.config_version_id=NEW.config_version_id AND root.kind='configuration'
                  AND root.encryption_algorithm='none'
                  AND root.media_type='application/vnd.cdnca.edge-site-root+json;version=1'
                  AND root.sha256=NEW.artifact_sha256 AND root.sha256=sha256(root.wire_bytes))))
    ) THEN
        RAISE EXCEPTION 'invalid security activation node artifact' USING ERRCODE='P3332';
    END IF;
    RETURN NEW;
END;
$$;
