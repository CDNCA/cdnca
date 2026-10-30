LOCK TABLE schema_migrations, l2_topology_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_270_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 270 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 270 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 270 AND migration_id = '270_l2_topology_default_region' AND
              checksum_sha256 = '1cd3686aa0036c42db838ce17741f9e15f5ca3c9b3333a520a4807176d4e4b27' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 270 rollback requires the exact verified 270 release head'
            USING ERRCODE = 'P2701';
    END IF;
    IF EXISTS (SELECT 1 FROM l2_topology_configs WHERE region = '') THEN
        RAISE EXCEPTION 'migration 270 rollback cannot discard default-region facts, including soft-deleted configs'
            USING ERRCODE = 'P2702';
    END IF;
END;
$migration_270_down$;

ALTER TABLE l2_topology_configs
    DROP CONSTRAINT l2_topology_configs_region_270_check,
    ADD CONSTRAINT l2_topology_configs_region_check CHECK (
        region = btrim(region) AND char_length(region) BETWEEN 1 AND 64 AND region !~ '[[:cntrl:]]'
    );
