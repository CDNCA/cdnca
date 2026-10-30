LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_356_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 355 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 355 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=355 AND
        migration_id='355_site_quick_block_overrides' AND
        checksum_sha256='907199b211564f0dfd565251048151c164bce43679aef7d7b223e754961e9e4d' AND
        down_checksum_sha256='f320bb5d52d5e56b7da375d0f3a392b8893e5caa0b22c53a5a01222279eb16a7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='cache_shared_across_domains'
       ) THEN
        RAISE EXCEPTION 'migration 356 requires the exact verified 355 release head' USING ERRCODE='P3560';
    END IF;
END;
$migration_356_up$;

-- r136 edge-followup: a site runtime v2 cache keys each object by the
-- request's own host (lower case, without the port), so the names a site
-- serves (aliases, hosts under a wildcard) never read each other's objects.
-- A site may instead share one cache across all its domains (所有域名共用缓存),
-- keyed by its primary domain. Off by default; existing sites key by host.
-- Any change of the column advances the scope's source revision (335).
ALTER TABLE sites
    ADD COLUMN cache_shared_across_domains boolean NOT NULL DEFAULT false;
