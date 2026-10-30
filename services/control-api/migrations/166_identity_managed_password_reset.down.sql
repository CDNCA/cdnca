LOCK TABLE schema_migrations,identity_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_166$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>166 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>166 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=166 AND migration_id='166_identity_managed_password_reset' AND
              checksum_sha256='4d3f0986b1c0f158ef971e08278fdb6a3766d49c32addf7e173991c1c5980916' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 166 rollback requires the exact verified 166 head'
            USING ERRCODE='P1660';
    END IF;
    IF EXISTS(
        SELECT 1 FROM identity_write_requests WHERE operation='identity.user.password.reset'
    ) THEN
        RAISE EXCEPTION 'migration 166 rollback would discard managed password reset receipts'
            USING ERRCODE='P1661';
    END IF;
END;
$migration_166$;

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create',
        'identity.user.update',
        'identity.self.update',
        'identity.membership.suspend'
    )),
    DROP CONSTRAINT identity_write_requests_secret_hash_check,
    ADD CONSTRAINT identity_write_requests_check CHECK (
        (operation = 'identity.user.create' AND secret_hash IS NOT NULL) OR
        (operation <> 'identity.user.create' AND secret_hash IS NULL)
    );
