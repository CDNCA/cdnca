-- 541 down：把 validate_plugin_webhook_actor_target_084 退回 540 的状态（532 up 留下的 SECURITY INVOKER、无 search_path），
-- 使 541 的 up/down/up 逐对象一致；函数体与 ACL 不动。
-- 回退到 531 的说明（以此为准）：之后执行的 532 down 已上线不能改，本脚本也无法影响它，它留下两处与全新 531 不同：
--   ① validate_acme_issuance_operation_snapshot_047 恢复成 531 之前的函数体，而不是 531 的；
--   ② validate_plugin_webhook_actor_target_084 同样被重建为 SECURITY INVOKER、无 search_path。
-- 停在 531 时须补两步：再执行一次 531_acme_platform_actor.up.sql 中 validate_acme_issuance_operation_snapshot_047 的
-- CREATE OR REPLACE（条件里调用 acme_runtime_actor_is_active_048），否则平台成员发起的 ACME 签发会被拒；再对 084
-- 执行一次 541 up 的两条 ALTER FUNCTION（SET search_path = 当前 schema, pg_catalog；SECURITY DEFINER）。
-- 继续回退到 530 及更早时 ① 不需要（531 down 本身恢复 530 的函数体），② 仍需要。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_541_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 541 OR
       (SELECT max(version) FROM schema_migrations) <> 541 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=541 AND
        migration_id='541_plugin_webhook_actor_definer' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 541 down requires the exact verified migration head' USING ERRCODE='P5411';
    END IF;
END;
$migration_541_down$;

DO $migration_541_invoker$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.validate_plugin_webhook_actor_target_084() SECURITY INVOKER', current_schema());
    EXECUTE format('ALTER FUNCTION %I.validate_plugin_webhook_actor_target_084() RESET search_path', current_schema());
END;
$migration_541_invoker$;
