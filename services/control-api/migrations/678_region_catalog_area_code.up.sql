-- 678（区域目录大区代码）；前驱 677_upgrade_cancel_expired_nodes。
-- 区域目录增加大区代码 area_code（libs/geoarea：global/east_asia/southeast_asia/south_asia/west_asia/
-- central_asia/europe/north_america/south_america/africa），空 = 未设置。一个区域要么设大区，要么设国家
-- （+中国省份），二者互斥；都不设 = 未设。大区清单改动只改 libs/geoarea/geoarea.go，并同步这里的 CHECK
-- （region_catalog_area_code_678_contract_test.go 逐项比对）。
-- 错误码：头检查 P6780；down 头检查 P6781。
LOCK TABLE schema_migrations, region_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_678_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 677 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 677 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=677 AND
        migration_id='677_upgrade_cancel_expired_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
            table_name='region_catalog' AND column_name='area_code'
       ) THEN
        RAISE EXCEPTION 'migration 678 requires the exact verified 677 release head' USING ERRCODE='P6780';
    END IF;
END;
$migration_678_up$;

ALTER TABLE region_catalog
    ADD COLUMN area_code text NOT NULL DEFAULT '',
    ADD CONSTRAINT region_catalog_area_code_678_check CHECK (
        area_code = '' OR area_code IN ('global','east_asia','southeast_asia','south_asia','west_asia','central_asia','europe','north_america','south_america','africa')
    ),
    ADD CONSTRAINT region_catalog_area_country_678_check CHECK (area_code = '' OR country_code = '');
