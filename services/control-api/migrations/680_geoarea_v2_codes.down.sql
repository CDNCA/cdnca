-- 680 回滚：CHECK 收回 678/679 的范围。仍有区域使用新代码、或仍有新代码线路记录时拒绝回滚（P6802）：
-- 先把这些区域改回旧代码（或国家）、让对应端点撤出线路（cnamelines 写空集并删行）再回滚。
LOCK TABLE schema_migrations, region_catalog, cname_carrier_line_records IN ACCESS EXCLUSIVE MODE;

DO $migration_680_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 680 OR
       (SELECT max(version) FROM schema_migrations) <> 680 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=680 AND
        migration_id='680_geoarea_v2_codes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 680 down requires the exact verified migration head' USING ERRCODE='P6801';
    END IF;
    IF EXISTS (SELECT 1 FROM region_catalog WHERE area_code <> '' AND area_code NOT IN ('global', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'north_america', 'south_america', 'africa')) OR
       EXISTS (SELECT 1 FROM cname_carrier_line_records WHERE line_scope IN ('asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'northern_europe', 'western_europe', 'southern_europe', 'eastern_europe', 'africa', 'northern_africa', 'western_africa', 'eastern_africa', 'middle_africa', 'southern_africa', 'north_america', 'northern_america', 'central_america', 'caribbean', 'south_america', 'oceania', 'australia_new_zealand', 'melanesia', 'micronesia', 'polynesia') AND
           line_scope NOT IN ('asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'north_america', 'south_america', 'africa')) THEN
        RAISE EXCEPTION 'migration 680 down refuses regions or line records using geoarea v2 codes' USING ERRCODE='P6802';
    END IF;
END;
$migration_680_down$;

ALTER TABLE cname_carrier_line_records DROP CONSTRAINT cname_carrier_line_records_line_scope_680_check,
    ADD CONSTRAINT cname_carrier_line_records_line_scope_679_check CHECK (
        line_scope IN ('telecom', 'unicom', 'mobile', 'overseas') OR
        line_scope IN ('asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'north_america', 'south_america', 'africa') OR
        line_scope ~ '^(北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|内蒙古|广西|西藏|宁夏|新疆):(telecom|unicom|mobile)$'
    );

ALTER TABLE region_catalog DROP CONSTRAINT region_catalog_area_code_680_check,
    ADD CONSTRAINT region_catalog_area_code_678_check CHECK (
        area_code = '' OR area_code IN ('global','east_asia','southeast_asia','south_asia','west_asia','central_asia','europe','north_america','south_america','africa')
    );
