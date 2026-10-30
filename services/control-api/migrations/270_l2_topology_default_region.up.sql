LOCK TABLE schema_migrations, l2_topology_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_270_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 269 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 269 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 269 AND migration_id = '269_node_host_metrics' AND
              checksum_sha256 = '7a6bfe3948bed1f878688d5341bf36deaa2b2ceab55e8cbcc3bbfe20a081478c' AND
              down_checksum_sha256 = 'b51f60964c0cc0aa3ecb4076c27577eb2e77f3ad210a4c8ba5a5e0ab569231d8' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 270 requires the exact verified 269 release head'
            USING ERRCODE = 'P2700';
    END IF;
END;
$migration_270_up$;

ALTER TABLE l2_topology_configs
    DROP CONSTRAINT l2_topology_configs_region_check,
    ADD CONSTRAINT l2_topology_configs_region_270_check CHECK (
        region = btrim(region) AND char_length(region) BETWEEN 0 AND 64 AND region !~ '[[:cntrl:]]'
    );
