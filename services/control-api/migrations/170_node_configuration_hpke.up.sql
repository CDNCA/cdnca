LOCK TABLE schema_migrations,configuration_artifacts IN ACCESS EXCLUSIVE MODE;

DO $migration_170$
DECLARE
    previous_constraint text;
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>169 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>169 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=169 AND migration_id='169_identity_verification_provider_sessions' AND
              checksum_sha256='e881ea03620506c0773bc8e22fa6fe93aff9b3bd5fae60feca8fafa0c0df254a' AND
              down_checksum_sha256='8426afd3af006fe6210de725ce39b03dab8d2c49469f85980187c05cb9e13daa' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('configuration_artifacts') IS NULL THEN
        RAISE EXCEPTION 'migration 170 requires the exact verified 169 release head' USING ERRCODE='P1700';
    END IF;

    SELECT conname INTO previous_constraint
    FROM pg_constraint
    WHERE conrelid='configuration_artifacts'::regclass AND contype='c' AND
          pg_get_constraintdef(oid) LIKE '%node_secret_bundle%' AND
          pg_get_constraintdef(oid) LIKE '%recipient_key_id IS NULL%';
    IF previous_constraint IS NULL THEN
        RAISE EXCEPTION 'migration 170 requires the legacy artifact kind/encryption constraint' USING ERRCODE='P1701';
    END IF;
    EXECUTE format('ALTER TABLE configuration_artifacts DROP CONSTRAINT %I',previous_constraint);
END;
$migration_170$;

ALTER TABLE configuration_artifacts
    ADD CONSTRAINT configuration_artifacts_kind_encryption_check CHECK (
        (kind = 'node_secret_bundle' AND encryption_algorithm = 'hpke_x25519_hkdf_sha256_aes_256_gcm' AND
         recipient_key_id IS NOT NULL AND char_length(recipient_key_id) BETWEEN 1 AND 128) OR
        (kind = 'configuration' AND encryption_algorithm = 'none' AND recipient_key_id IS NULL) OR
        (kind = 'configuration' AND encryption_algorithm = 'hpke_x25519_hkdf_sha256_aes_256_gcm' AND
         recipient_key_id ~ '^x25519:[0-9a-f]{64}$')
    );
