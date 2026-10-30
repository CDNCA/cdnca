-- 588（fix-cachequota，占位号，合入时主会话按集成头连号）：刷新预热每日额度改按账号（租户作用域）计算。
-- ①cache_operation_account_quotas：管理员给单个账号设的三项每日上限，列为空 = 跟随系统设置默认值；
-- ②按账号计数的部分索引（同一账号当天用户提交的任务，系统补发 parent_operation_id 非空不计）。
-- 前驱 587（plugin_promo_charge_notice），守卫钉 587 校验和。
LOCK TABLE schema_migrations, cache_operations IN ACCESS EXCLUSIVE MODE;

DO $migration_588_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 587 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 587 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=587 AND
        migration_id='587_plugin_promo_charge_notice' AND
        checksum_sha256='74a2e8867020908f3b0300d3e8c99d14b1a42c375dae5bb390d1ef2e7506a40a' AND
        down_checksum_sha256='3e0af927e2169681ab11334b803d5b9231df36ec201770334c36a59677ae6b13' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('cache_operation_account_quotas') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 588 requires the exact verified 587 release head' USING ERRCODE='P5880';
    END IF;
END;
$migration_588_up$;

-- 一个账号（租户作用域）一行；上限范围与系统设置 → 资源配置 → 缓存与解锁一致，另允许 0（该账号当天不能提交）。
CREATE TABLE cache_operation_account_quotas (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE CASCADE,
    url_purge_limit integer CHECK (url_purge_limit BETWEEN 0 AND 10000000),
    directory_purge_limit integer CHECK (directory_purge_limit BETWEEN 0 AND 1000000),
    prewarm_limit integer CHECK (prewarm_limit BETWEEN 0 AND 10000000),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL
);

CREATE FUNCTION protect_cache_operation_account_quota_588()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant') THEN
        RAISE EXCEPTION 'cache account quotas belong to a tenant scope' USING ERRCODE='P5881';
    END IF;
    IF TG_OP = 'INSERT' AND NEW.revision <> 1 OR
       TG_OP = 'UPDATE' AND (NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.revision <> OLD.revision + 1) THEN
        RAISE EXCEPTION 'cache account quota revision must advance by one' USING ERRCODE='P5882';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER cache_operation_account_quotas_protect_588
BEFORE INSERT OR UPDATE ON cache_operation_account_quotas
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_account_quota_588();

CREATE INDEX cache_operations_account_daily_588_idx
    ON cache_operations (scope_id, created_at) WHERE parent_operation_id IS NULL;

GRANT SELECT, INSERT, UPDATE ON cache_operation_account_quotas TO cdnca_control_app, cdnca_control_runtime;
