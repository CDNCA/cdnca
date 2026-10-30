LOCK TABLE schema_migrations, security_policy_activation_node_artifacts_333 IN ACCESS EXCLUSIVE MODE;

DO $migration_426_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 425 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 425 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=425 AND
        migration_id='425_waf_adapt_cookies' AND
        checksum_sha256='ab8f82e51340a050dd670d3e396ee986d05790ee7c0824dfd028afa09815b135' AND
        down_checksum_sha256='ef214d732072f69dd538451c2b961998d32e402d5e45c857aee80546bb2840c8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 426 requires the exact verified 425 release head' USING ERRCODE='P4260';
    END IF;
END;
$migration_426_up$;

-- 426（r136 dr-d13-c3b，主会话分配 421；本地连号占位，合入时改号）。
-- Dynamic routing is the only node runtime (1.0.35): the v1 site object
-- root (site runtime v8) is no longer published, so a security activation
-- node row may only name the v2 root (cdnca.edge-site-root/v2).
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
                  AND root.media_type='application/vnd.cdnca.edge-site-root+json;version=2'
                  AND root.sha256=NEW.artifact_sha256 AND root.sha256=sha256(root.wire_bytes))))
    ) THEN
        RAISE EXCEPTION 'invalid security activation node artifact' USING ERRCODE='P3332';
    END IF;
    RETURN NEW;
END;
$$;
