-- 580（fix-logowner LOG-01 占位 599，merge-p22 按集成头连号改为 580，前驱钉 579_background_job_producer_cancellation）。
-- 访问日志导出申请的归属与幂等从"登录会话"改为"账号 + 查询范围"：
--   ①幂等键按账号唯一（actor_scope_id,actor_user_id,idempotency_key），重新登录后同一键仍回放原申请；
--   ②同一账号 + 同一查询范围（scope_id + request_digest，request_digest 为规范化 filter 的哈希）按代（scope_generation）
--     唯一：最新一代仍在处理或产物未过期就复用，失败可重试时在原申请上重试，产物过期或重试用尽才建下一代；
--   ③credential_id 只记"由哪个会话发起"（审计），不再参与归属判断；下载授权仍绑当前会话（grants.session_id）。
-- 用户 10-17：1.0.35 为初始版本、上线全部重装，不做旧版兼容。
LOCK TABLE schema_migrations, analytics_log_exports_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_580_up$
DECLARE legacy_unique text;
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 579 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 579 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=579 AND
        migration_id='579_background_job_producer_cancellation' AND
        checksum_sha256='12bd4565101e5f39836d9ead33891c378c08ad080b385a8bdbad5fe456cea40e' AND
        down_checksum_sha256='4ce4db2e03c79289a21f326a7a99d5a4943de123caec831f8d38f6752ae0fd07' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='analytics_log_exports_v1' AND column_name='scope_generation'
       ) THEN
        RAISE EXCEPTION 'migration 580 requires the exact verified 579 release head' USING ERRCODE='P5800';
    END IF;
    SELECT conname INTO legacy_unique FROM pg_catalog.pg_constraint
    WHERE conrelid='analytics_log_exports_v1'::regclass AND contype='u' AND
          pg_get_constraintdef(oid)='UNIQUE (actor_scope_id, actor_user_id, credential_kind, credential_id, idempotency_key)';
    IF legacy_unique IS NULL THEN
        RAISE EXCEPTION 'migration 580 cannot find the session-bound export idempotency key' USING ERRCODE='P5800';
    END IF;
    EXECUTE format('ALTER TABLE analytics_log_exports_v1 DROP CONSTRAINT %I', legacy_unique);
    -- 旧数据（测试库）同一账号内重复的幂等键或同范围多份申请无法确定归属：拒绝而不是挑一份。
    IF EXISTS (
        SELECT 1 FROM analytics_log_exports_v1
        GROUP BY actor_scope_id,actor_user_id,idempotency_key HAVING count(*) > 1
    ) OR EXISTS (
        SELECT 1 FROM analytics_log_exports_v1
        GROUP BY actor_scope_id,actor_user_id,scope_id,request_digest HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'migration 580 refuses duplicate export requests within one account' USING ERRCODE='P5801';
    END IF;
END;
$migration_580_up$;

ALTER TABLE analytics_log_exports_v1
    ADD COLUMN scope_generation integer NOT NULL DEFAULT 1 CHECK (scope_generation > 0),
    ADD CONSTRAINT analytics_log_exports_owner_key_580
        UNIQUE (actor_scope_id,actor_user_id,idempotency_key),
    ADD CONSTRAINT analytics_log_exports_owner_scope_580
        UNIQUE (actor_scope_id,actor_user_id,scope_id,request_digest,scope_generation);
ALTER TABLE analytics_log_exports_v1 ALTER COLUMN scope_generation DROP DEFAULT;

CREATE INDEX analytics_log_exports_owner_created_580_idx
    ON analytics_log_exports_v1(scope_id,actor_scope_id,actor_user_id,created_at DESC,id DESC);

COMMENT ON TABLE analytics_log_exports_v1 IS
    'Runtime appends audit_events actions analytics_log.export.create, analytics_log.export.retry, analytics_log.export.complete, analytics_log.export.grant, analytics_log.export.download and analytics_log.export.reject transactionally. Ownership is account + query scope (580); credential_id records the creating session only.';
