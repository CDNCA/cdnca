-- 679（CNAME 线路大区 scope）；前驱 678_region_catalog_area_code。
-- 按大区分线路：cname_carrier_line_records.line_scope 放开大区线路 scope（cnamelines.AreaScope）：
-- libs/geoarea 除 global 以外的九个大区代码，以及亚洲各大区在服务商没有亚区线路时回退用的 asia。
-- global 不入表（全球节点只在默认线路）。运营商/境外与 609 的省份线路保持原样。
-- 大区清单改动只改 libs/geoarea/geoarea.go，并同步这里的列表（cname_line_area_scopes_679_contract_test.go 比对）。
-- 错误码：头检查 P6790；down 头检查 P6791；down 遇到仍有大区线路记录 P6792。
LOCK TABLE schema_migrations, cname_carrier_line_records IN ACCESS EXCLUSIVE MODE;

DO $migration_679_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 678 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 678 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=678 AND
        migration_id='678_region_catalog_area_code' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='cname_carrier_line_records'::regclass AND
            conname='cname_carrier_line_records_line_scope_609_check'
       ) THEN
        RAISE EXCEPTION 'migration 679 requires the exact verified 678 release head' USING ERRCODE='P6790';
    END IF;
END;
$migration_679_up$;

ALTER TABLE cname_carrier_line_records DROP CONSTRAINT cname_carrier_line_records_line_scope_609_check,
    ADD CONSTRAINT cname_carrier_line_records_line_scope_679_check CHECK (
        line_scope IN ('telecom', 'unicom', 'mobile', 'overseas') OR
        line_scope IN ('asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'north_america', 'south_america', 'africa') OR
        line_scope ~ '^(北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|内蒙古|广西|西藏|宁夏|新疆):(telecom|unicom|mobile)$'
    );
