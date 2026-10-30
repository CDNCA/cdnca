LOCK TABLE schema_migrations,site_origin_route_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_177$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>176 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>176 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=176 AND migration_id='176_site_ipv6_rollout_state' AND
              checksum_sha256='51843578ad26276dd4d5ebca731f304f86fa8b572ad46b8fd9cf2eb09263a689' AND
              down_checksum_sha256='0764502f61d4f963ca8bd8f2486ba4edfbe3ced3b52011d7c4574eacf67e3c04' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='site_origin_route_configs' AND
              column_name='ingress_source_enabled'
    ) THEN
        RAISE EXCEPTION 'migration 177 requires the exact verified 176 release head and an untouched ingress-source origin schema'
            USING ERRCODE='P1770';
    END IF;
END;
$migration_177$;

ALTER TABLE site_origin_route_configs
    ADD COLUMN ingress_source_enabled boolean NOT NULL DEFAULT false;
