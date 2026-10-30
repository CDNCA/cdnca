LOCK TABLE schema_migrations, tenant_member_password_reset_results IN ACCESS EXCLUSIVE MODE;

DO $migration_487_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 487 OR
       (SELECT max(version) FROM schema_migrations) <> 487 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=487 AND
        migration_id='487_tenant_member_password_reset_results' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 487 down requires the exact verified migration head' USING ERRCODE='P4871';
    END IF;
END;
$migration_487_down$;

-- 留存的是 10 分钟内可取回的临时密码密文，回退时直接丢弃（成员仍可用已设置的密码登录并被要求改密）。
DROP TABLE tenant_member_password_reset_results;
