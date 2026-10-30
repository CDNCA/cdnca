LOCK TABLE schema_migrations,identity_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_166$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>165 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>165 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=165 AND migration_id='165_package_period_reset_workload_authority' AND
              checksum_sha256='8cbf3c38d4619f7f4a52b4a90c530b51cef452037e26e5a7f28b44fcdc74c915' AND
              down_checksum_sha256='5dbf55aafcda5000d0c8a492aeb81a65d9bcfd7d74a44fe57fde384e4bc8de70' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 166 requires the exact verified 165 release head'
            USING ERRCODE='P1660';
    END IF;
END;
$migration_166$;

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create',
        'identity.user.update',
        'identity.self.update',
        'identity.membership.suspend',
        'identity.user.password.reset'
    )),
    DROP CONSTRAINT identity_write_requests_check,
    ADD CONSTRAINT identity_write_requests_secret_hash_check CHECK (
        (operation IN ('identity.user.create','identity.user.password.reset') AND secret_hash IS NOT NULL) OR
        (operation NOT IN ('identity.user.create','identity.user.password.reset') AND secret_hash IS NULL)
    );
