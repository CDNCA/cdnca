-- 680（两级大区代码）；前驱 679_cname_line_area_scopes。
-- libs/geoarea 改为两级（全球 → 大洲 → 区域，联合国 M49 国家归属）：放宽 678 的
-- region_catalog.area_code 与 679 的 cname_carrier_line_records.line_scope 的 CHECK 到全部新代码。
-- 现有代码含义不变，已存数据无需改写。area_code：全部 geoarea 代码或空（与国家互斥照旧）；
-- line_scope：运营商/境外、全部 geoarea 代码（global 除外，全球节点只在默认线路）、609 省份线路照旧。
-- 大区清单改动只改 libs/geoarea/geoarea.go，并同步这里的列表（geoarea_v2_codes_680_contract_test.go 逐项比对）。
-- 错误码：头检查 P6800；down 头检查 P6801；down 遇到仍在使用新代码的数据 P6802。
LOCK TABLE schema_migrations, region_catalog, cname_carrier_line_records IN ACCESS EXCLUSIVE MODE;

DO $migration_680_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 679 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 679 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=679 AND
        migration_id='679_cname_line_area_scopes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='region_catalog'::regclass AND
            conname='region_catalog_area_code_678_check'
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='cname_carrier_line_records'::regclass AND
            conname='cname_carrier_line_records_line_scope_679_check'
       ) THEN
        RAISE EXCEPTION 'migration 680 requires the exact verified 679 release head' USING ERRCODE='P6800';
    END IF;
END;
$migration_680_up$;

ALTER TABLE region_catalog DROP CONSTRAINT region_catalog_area_code_678_check,
    ADD CONSTRAINT region_catalog_area_code_680_check CHECK (
        area_code = '' OR area_code IN ('global', 'asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'northern_europe', 'western_europe', 'southern_europe', 'eastern_europe', 'africa', 'northern_africa', 'western_africa', 'eastern_africa', 'middle_africa', 'southern_africa', 'north_america', 'northern_america', 'central_america', 'caribbean', 'south_america', 'oceania', 'australia_new_zealand', 'melanesia', 'micronesia', 'polynesia')
    );

ALTER TABLE cname_carrier_line_records DROP CONSTRAINT cname_carrier_line_records_line_scope_679_check,
    ADD CONSTRAINT cname_carrier_line_records_line_scope_680_check CHECK (
        line_scope IN ('telecom', 'unicom', 'mobile', 'overseas') OR
        line_scope IN ('asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'northern_europe', 'western_europe', 'southern_europe', 'eastern_europe', 'africa', 'northern_africa', 'western_africa', 'eastern_africa', 'middle_africa', 'southern_africa', 'north_america', 'northern_america', 'central_america', 'caribbean', 'south_america', 'oceania', 'australia_new_zealand', 'melanesia', 'micronesia', 'polynesia') OR
        line_scope ~ '^(北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|内蒙古|广西|西藏|宁夏|新疆):(telecom|unicom|mobile)$'
    );
