LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_307_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 306 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 306 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=306 AND
        migration_id='306_security_activation_capability_waits' AND
        checksum_sha256='12ac6e3078913063754f16f2b97d8e9f6a5a3b518011fc363e77569f6ccc4242' AND
        down_checksum_sha256='bbdfce794d3382d532494f7d71b6a7bc2179cbb30e8227eb844b0b388d753b68' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='site_origin_pools' AND column_name='keepalive_enabled'
       ) THEN
        RAISE EXCEPTION 'migration 307 requires the exact verified 306 release head' USING ERRCODE='P3070';
    END IF;
END;
$migration_307_up$;

-- NF01: the node's nginx (1.29.7+) already reuses origin connections with no
-- upstream keepalive directive (32 idle connections, 60s idle timeout), and
-- sites could not change or turn that off. The defaults keep exactly that;
-- a site may lower the idle timeout below its origin's own keepalive timeout
-- (otherwise the origin closes a connection the edge is about to reuse) or
-- turn reuse off.
ALTER TABLE site_origin_pools
    ADD COLUMN keepalive_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN keepalive_idle_timeout_ms integer NOT NULL DEFAULT 60000,
    ADD CONSTRAINT site_origin_pools_keepalive_idle_timeout_307
        CHECK (keepalive_idle_timeout_ms BETWEEN 1000 AND 300000);
