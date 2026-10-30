-- 576 回滚：去掉区域目录的国家码/省码。
LOCK TABLE schema_migrations, region_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_576_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 576 OR
       (SELECT max(version) FROM schema_migrations) <> 576 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=576 AND
        migration_id='576_region_catalog_geo_codes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 576 down requires the exact verified migration head' USING ERRCODE='P5761';
    END IF;
END;
$migration_576_down$;

ALTER TABLE region_catalog
    DROP CONSTRAINT region_catalog_province_code_576_check,
    DROP CONSTRAINT region_catalog_country_code_576_check,
    DROP COLUMN province_code,
    DROP COLUMN country_code;
