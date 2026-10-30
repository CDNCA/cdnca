LOCK TABLE schema_migrations, deployment_status_events IN ACCESS EXCLUSIVE MODE;

DO $migration_564_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 563 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 563 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=563 AND
        migration_id='563_autodefense_follow_platform' AND
        checksum_sha256='ee731b72e24b4309cae364109ea76c045fd46303423ce962e7c8ffe1afe2ac01' AND
        down_checksum_sha256='472166bad371ea77fe30942aa0cc41faf171f8f71f9308e9ef371f579cdbc313' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'deployment_status_events' AND column_name = 'error_code'
       ) THEN
        RAISE EXCEPTION 'migration 564 requires the exact verified 563 release head' USING ERRCODE='P5640';
    END IF;
END;
$migration_564_up$;

-- 564（fix-cfgflow2 §1，占位，合入时由主会话改号与改钉前驱）。
-- 节点在激活前拒绝的 APPLY（节点已在更新版本 ERROR_CODE_STALE_ATTEMPT、该版本已被回滚
-- ERROR_CODE_REVOKED，运行配置未变）是“已忽略旧发布”，不是失败：灰度失败阈值、发布完成判定、
-- 自动发布结果与重试都要在 SQL 里认出它。节点回执的 ProtocolError 码原样记一列（只在失败类状态上有），
-- 判定规则见 internal/edgedeployment DeploymentSuperseded；已有行保持 NULL（视为普通失败）。
ALTER TABLE deployment_status_events ADD COLUMN error_code text
    CONSTRAINT deployment_status_events_error_code_564 CHECK (
        error_code IS NULL OR
        (error_code ~ '^ERROR_CODE_[A-Z_]{1,64}$' AND state IN ('failed', 'rollback_failed'))
    );
