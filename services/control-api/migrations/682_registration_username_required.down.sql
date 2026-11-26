LOCK TABLE schema_migrations, platform_system_user_settings IN ACCESS EXCLUSIVE MODE;

-- 682 回滚不回写 username_required：682 之前的版本不读这一项（注册始终要求用户名），保留 true 与
-- 回滚后的实际行为一致；原值是 false 还是缺失也无从区分。只校验确是 682 的已验证发布头。
DO $migration_682_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 682 OR
       (SELECT max(version) FROM schema_migrations) <> 682 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=682 AND
        migration_id='682_registration_username_required' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 682 rollback requires the exact verified 682 release head' USING ERRCODE='P6821';
    END IF;
END;
$migration_682_down$;
