LOCK TABLE schema_migrations, security_policy_activation_node_artifacts_333 IN ACCESS EXCLUSIVE MODE;

DO $migration_399_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 398 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 398 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=398 AND
        migration_id='398_tenant_member_invitations' AND
        checksum_sha256='a380fd93568e70d22bd9fb4f842686225b66d4ed2bd86a72a9b6d16a7e2c882e' AND
        down_checksum_sha256='ef525337ac937c5974d51c66e657f2d01223d40a028345c56a19d8cdb8a394dd' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 399 requires the exact verified 398 release head' USING ERRCODE='P3990';
    END IF;
END;
$migration_399_up$;

-- 399（r136 dr-d13-a3，占位：合入时接在当时集成头之后）。
-- A site_runtime 9 (dynamic routing) security activation candidate is
-- delivered as the v2 signed root (cdnca.edge.site-root/v2) plus a key
-- envelope per node; the node reports running the root's digest. 354 only
-- accepted the v1 root, so every v9 candidate's node row was refused
-- (P3332). Accept either root; everything else is unchanged.
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
                  AND root.media_type IN ('application/vnd.cdnca.edge-site-root+json;version=1',
                                         'application/vnd.cdnca.edge-site-root+json;version=2')
                  AND root.sha256=NEW.artifact_sha256 AND root.sha256=sha256(root.wire_bytes))))
    ) THEN
        RAISE EXCEPTION 'invalid security activation node artifact' USING ERRCODE='P3332';
    END IF;
    RETURN NEW;
END;
$$;
