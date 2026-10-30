LOCK TABLE schema_migrations, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_472_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 471 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 471 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=471 AND
        migration_id='471_theme_block_pages' AND
        checksum_sha256='e660fa014659b1112cad7a67211dba329c2ae3faf13acb09ff32be6c48f54b3e' AND
        down_checksum_sha256='4bd9ad669a400c8026d74a679e2213f977312a7244f44ff6a8d31f7de22ee126' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='sites' AND column_name='cache_status_header'
       ) THEN
        RAISE EXCEPTION 'migration 472 requires the exact verified 471 release head' USING ERRCODE='P4720';
    END IF;
END;
$migration_472_up$;

-- r136 cache-status-header (user 10-23 21:30): 响应头显示缓存状态. The node
-- answers X-CDN-Cache: <upstream_cache_status> (HIT, MISS, EXPIRED, ...; no node
-- name or address) for a site with the switch on. On by default. A site at
-- attack escalation level B or above is published with it off (the node
-- reads only the published switch). Any change of the column advances the
-- scope's source revision (335).
ALTER TABLE sites
    ADD COLUMN cache_status_header boolean NOT NULL DEFAULT true;
