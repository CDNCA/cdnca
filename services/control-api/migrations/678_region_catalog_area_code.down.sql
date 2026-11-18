-- 678 回滚：去掉区域目录的大区代码。
LOCK TABLE schema_migrations, region_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_678_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 678 OR
       (SELECT max(version) FROM schema_migrations) <> 678 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=678 AND
        migration_id='678_region_catalog_area_code' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 678 down requires the exact verified migration head' USING ERRCODE='P6781';
    END IF;
END;
$migration_678_down$;

ALTER TABLE region_catalog
    DROP CONSTRAINT region_catalog_area_country_678_check,
    DROP CONSTRAINT region_catalog_area_code_678_check,
    DROP COLUMN area_code;
