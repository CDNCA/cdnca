LOCK TABLE schema_migrations,sites IN ACCESS EXCLUSIVE MODE;

DO $migration_160$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>159 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>159 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=159 AND migration_id='159_account_registration' AND
              checksum_sha256='8a4d250bff304aed957f58390cab80818b0c22a6be24e08113a53c764d35d787' AND
              down_checksum_sha256='81ca97f71205f7743bc78b5104958ca4e81ab55026d75644799e5fe220d899e2' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='tls_protocols'
    ) THEN
        RAISE EXCEPTION 'migration 160 requires a contiguous verified 159 release head'
            USING ERRCODE='P1600';
    END IF;
END;
$migration_160$;

ALTER TABLE sites
    ADD COLUMN tls_protocols text[]
        DEFAULT ARRAY['TLSv1.2','TLSv1.3']::text[]
        NOT NULL,
    ADD CONSTRAINT sites_tls_protocols_valid_160 CHECK (
        cardinality(tls_protocols) BETWEEN 1 AND 6 AND
        array_position(tls_protocols,NULL) IS NULL AND
        tls_protocols <@ ARRAY['SSLv2','SSLv3','TLSv1','TLSv1.1','TLSv1.2','TLSv1.3']::text[] AND
        (
            tls_protocols = ARRAY['TLSv1.2','TLSv1.3']::text[] OR
            tls_protocols && ARRAY['SSLv2','SSLv3','TLSv1','TLSv1.1']::text[]
        )
    );
