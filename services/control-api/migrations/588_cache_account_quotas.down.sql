-- 588 回退：删账号额度覆盖表与按账号计数索引（额度回到系统设置默认值）。
LOCK TABLE schema_migrations, cache_operations, cache_operation_account_quotas IN ACCESS EXCLUSIVE MODE;

DO $migration_588_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 588 OR
       (SELECT max(version) FROM schema_migrations) <> 588 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=588 AND
        migration_id='588_cache_account_quotas' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 588 down requires the exact verified migration head' USING ERRCODE='P5883';
    END IF;
END;
$migration_588_down$;

DROP INDEX cache_operations_account_daily_588_idx;
DROP TABLE cache_operation_account_quotas;
DROP FUNCTION protect_cache_operation_account_quota_588();
