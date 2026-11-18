-- 679 回滚：line_scope 收回 609 的范围。仍有大区线路记录时拒绝回滚（P6792）：先让大区端点撤出
-- （cnamelines 把空集写到线路并删行）再回滚，不留无人管理的 DNS 记录。
LOCK TABLE schema_migrations, cname_carrier_line_records IN ACCESS EXCLUSIVE MODE;

DO $migration_679_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 679 OR
       (SELECT max(version) FROM schema_migrations) <> 679 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=679 AND
        migration_id='679_cname_line_area_scopes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 679 down requires the exact verified migration head' USING ERRCODE='P6791';
    END IF;
    IF EXISTS (SELECT 1 FROM cname_carrier_line_records WHERE line_scope IN ('asia', 'east_asia', 'southeast_asia', 'south_asia', 'west_asia', 'central_asia', 'europe', 'north_america', 'south_america', 'africa')) THEN
        RAISE EXCEPTION 'migration 679 down refuses area line records' USING ERRCODE='P6792';
    END IF;
END;
$migration_679_down$;

ALTER TABLE cname_carrier_line_records DROP CONSTRAINT cname_carrier_line_records_line_scope_679_check,
    ADD CONSTRAINT cname_carrier_line_records_line_scope_609_check CHECK (
        line_scope IN ('telecom', 'unicom', 'mobile', 'overseas') OR
        line_scope ~ '^(北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|内蒙古|广西|西藏|宁夏|新疆):(telecom|unicom|mobile)$'
    );
