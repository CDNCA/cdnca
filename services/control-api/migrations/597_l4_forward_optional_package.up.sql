-- 597（merge-p27，按"号连续"排在 596 之后）：
-- 四层转发的 package_subscription_id 允许为空，供社区版（无套餐）四层转发使用。
-- 商业版代码始终写非空；外键 l4_forwards_scope_package_092 对 NULL 不生效，非空行仍受其约束。
-- 已核对 l4_forwards 上的触发器函数（214/248/293/334/506/507 最新定义）都不读该列；
-- 507 的 dns_reconcile_stream_config_digest_507 把它放进 jsonb 数组，NULL 记作 json null，不报错。
-- 前驱：596_theme_user_follows_admin。
LOCK TABLE schema_migrations, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_597_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 596 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 596 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=596 AND
        migration_id='596_theme_user_follows_admin' AND
        checksum_sha256='81a4f197f6b9eed073ce3da1c2ca7cd95ae6821d192c0fe82b8f56726a62ccd9' AND
        down_checksum_sha256='c68be84368d1da6ed766f03fb831d112723a354149d6449f1d1a7c70985f541e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='l4_forwards' AND
            column_name='package_subscription_id' AND is_nullable='NO'
       ) THEN
        RAISE EXCEPTION 'migration 597 requires the exact verified 596 release head' USING ERRCODE='P5970';
    END IF;
END;
$migration_597_up$;

ALTER TABLE l4_forwards ALTER COLUMN package_subscription_id DROP NOT NULL;
