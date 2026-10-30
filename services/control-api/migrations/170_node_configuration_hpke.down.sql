LOCK TABLE schema_migrations,configuration_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_170$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>170 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>170 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=170 AND migration_id='170_node_configuration_hpke' AND
              checksum_sha256='140d1689a8d3ce17e34cc8bc46598711364d9fe129ec36bb3e5f591c71f8f089' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=169 AND migration_id='169_identity_verification_provider_sessions' AND
              checksum_sha256='e881ea03620506c0773bc8e22fa6fe93aff9b3bd5fae60feca8fafa0c0df254a' AND
              down_checksum_sha256='8426afd3af006fe6210de725ce39b03dab8d2c49469f85980187c05cb9e13daa' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 170 rollback requires the exact verified 170 head' USING ERRCODE='P1700';
    END IF;
    IF EXISTS(
        SELECT 1 FROM configuration_artifacts
        WHERE kind = 'configuration' AND encryption_algorithm = 'hpke_x25519_hkdf_sha256_aes_256_gcm'
    ) THEN
        RAISE EXCEPTION 'migration 170 rollback would discard encrypted configuration compatibility' USING ERRCODE='P1706';
    END IF;
END;
$migration_170$;

ALTER TABLE configuration_artifacts
    DROP CONSTRAINT configuration_artifacts_kind_encryption_check;

ALTER TABLE configuration_artifacts
    ADD CONSTRAINT configuration_artifacts_kind_encryption_check CHECK (
        (kind = 'node_secret_bundle' AND encryption_algorithm = 'hpke_x25519_hkdf_sha256_aes_256_gcm' AND
         recipient_key_id IS NOT NULL AND char_length(recipient_key_id) BETWEEN 1 AND 128) OR
        (kind = 'configuration' AND encryption_algorithm = 'none' AND recipient_key_id IS NULL)
    );
