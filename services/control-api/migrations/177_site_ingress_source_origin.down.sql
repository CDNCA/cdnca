LOCK TABLE schema_migrations,site_origin_route_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_177_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>177 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>177 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=177 AND migration_id='177_site_ingress_source_origin' AND
              checksum_sha256='2c30c0ae8ac61027f16ad024e562b350ff3737d684fc1115491acfd65c0da58c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 177 rollback requires the exact verified 177 head' USING ERRCODE='P1771';
    END IF;
    IF EXISTS (
        SELECT 1 FROM site_origin_route_configs WHERE ingress_source_enabled
    ) THEN
        RAISE EXCEPTION 'migration 177 rollback would discard enabled ingress-source origin facts'
            USING ERRCODE='P1772';
    END IF;
END;
$migration_177_down$;

ALTER TABLE site_origin_route_configs DROP COLUMN ingress_source_enabled;
