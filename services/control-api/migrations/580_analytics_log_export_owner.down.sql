-- 580 回滚：导出申请归属恢复为登录会话。已建过第二代（scope_generation > 1）时拒绝回滚（不静默丢代际事实）。
LOCK TABLE schema_migrations, analytics_log_exports_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_580_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 580 OR
       (SELECT max(version) FROM schema_migrations) <> 580 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=580 AND
        migration_id='580_analytics_log_export_owner' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 580 down requires the exact verified migration head' USING ERRCODE='P5802';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_log_exports_v1 WHERE scope_generation > 1) THEN
        RAISE EXCEPTION 'migration 580 down refuses export scope generations beyond the first' USING ERRCODE='P5803';
    END IF;
END;
$migration_580_down$;

DROP INDEX analytics_log_exports_owner_created_580_idx;
ALTER TABLE analytics_log_exports_v1
    DROP CONSTRAINT analytics_log_exports_owner_scope_580,
    DROP CONSTRAINT analytics_log_exports_owner_key_580,
    DROP COLUMN scope_generation,
    ADD UNIQUE (actor_scope_id,actor_user_id,credential_kind,credential_id,idempotency_key);

COMMENT ON TABLE analytics_log_exports_v1 IS
    'Runtime appends audit_events actions analytics_log.export.create, analytics_log.export.complete, analytics_log.export.grant, analytics_log.export.download and analytics_log.export.reject transactionally.';
