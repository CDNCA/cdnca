-- 559 回滚：删掉站点解析检查结果。旧版本没有 access_readiness 字段，不读本表；结果可随时由后台检查重建。
LOCK TABLE schema_migrations, site_dns_resolution_checks IN ACCESS EXCLUSIVE MODE;

DO $migration_559_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 559 OR
       (SELECT max(version) FROM schema_migrations) <> 559 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=559 AND
        migration_id='559_site_dns_resolution_checks' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 559 down requires the exact verified migration head' USING ERRCODE='P5591';
    END IF;
END;
$migration_559_down$;

DROP TABLE site_dns_resolution_checks;
