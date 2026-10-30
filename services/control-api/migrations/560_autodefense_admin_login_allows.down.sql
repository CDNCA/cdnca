-- 560 回滚：删掉管理登录来源 IP 自动加白表；节点在下一次快照里不再收到 admin_login 白名单。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_560_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 560 OR
       (SELECT max(version) FROM schema_migrations) <> 560 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=560 AND
        migration_id='560_autodefense_admin_login_allows' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 560 down requires the exact verified migration head' USING ERRCODE='P5601';
    END IF;
END;
$migration_560_down$;

DROP TABLE autodefense_admin_login_allows;
