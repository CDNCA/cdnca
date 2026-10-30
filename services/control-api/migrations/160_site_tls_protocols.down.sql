LOCK TABLE schema_migrations,sites IN ACCESS EXCLUSIVE MODE;

DO $migration_160$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>160 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>160 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=160 AND migration_id='160_site_tls_protocols' AND
              checksum_sha256='697dfe854b2e4423d799348e35776ab406f303a104a52c232ff2d5af0db1fe7f' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=159 AND migration_id='159_account_registration' AND
              checksum_sha256='8a4d250bff304aed957f58390cab80818b0c22a6be24e08113a53c764d35d787' AND
              down_checksum_sha256='81ca97f71205f7743bc78b5104958ca4e81ab55026d75644799e5fe220d899e2' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 160 rollback requires the exact verified 160 head'
            USING ERRCODE='P1600';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sites
        WHERE tls_protocols IS DISTINCT FROM ARRAY['TLSv1.2','TLSv1.3']::text[]
    ) THEN
        RAISE EXCEPTION 'migration 160 rollback would discard non-canonical TLS remediation facts'
            USING ERRCODE='P1601';
    END IF;
END;
$migration_160$;

ALTER TABLE sites DROP COLUMN tls_protocols;
