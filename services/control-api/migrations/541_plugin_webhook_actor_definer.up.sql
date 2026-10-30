-- 541（fix-finalgaps2，主会话 10-27 分配）：修 532 留下的两处缺陷。532 的 up/down 都不能改（73 已记两者校验和，533 守卫钉 532）。
-- ① 532 up 用 CREATE OR REPLACE 重建 validate_plugin_webhook_actor_target_084 时没带 084 设的
--    SECURITY DEFINER 与 SET search_path（CREATE OR REPLACE 会把未写的属性重置为默认），73 线上即此状态：
--    触发器以调用者权限执行、search_path 未钉。这里按 084 原写法恢复两项（search_path = 当前 schema, pg_catalog）；
--    函数体与 ACL 不动（ACL 在 CREATE OR REPLACE 后保留，仍是 084 的 REVOKE ALL FROM PUBLIC）。
-- ② 532 down 把 validate_acme_issuance_operation_snapshot_047 恢复成 531 之前的函数体（直接查目标租户成员关系），
--    而不是 531 的函数体（调 acme_runtime_actor_is_active_048，允许平台成员）；532 down 重建 084 时同样丢了两项设置。
--    所以从本迁移一路回退到 531 后，047 停在 530 的规则（平台成员发起的 ACME 签发被拒），084 又回到调用者权限。
--    532 down 改不了，541 也无法影响之后才执行的 532 down；回退链上以 541 down 头注为准：541 down 只把本迁移的
--    改动退回 540 的状态，停在 531 时按头注补两步（重建 531 的 047、对 084 重做本迁移的两条 ALTER）。
-- 前驱 540（access_log_fields），守卫钉 540 校验和。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_541_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 540 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 540 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=540 AND
        migration_id='540_access_log_fields' AND
        checksum_sha256='a14454cda5578790e3e260bd9eb2a3ca929245ec0c2edc3210b2d247c95bc7df' AND
        down_checksum_sha256='bacd52f5fd4ed3be005fe64a10990c2fb806fd5c5501f5de7339baddf98fed85' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('validate_plugin_webhook_actor_target_084()') IS NULL THEN
        RAISE EXCEPTION 'migration 541 requires the exact verified 540 release head' USING ERRCODE='P5410';
    END IF;
END;
$migration_541_up$;

DO $migration_541_definer$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.validate_plugin_webhook_actor_target_084() SET search_path = %I, pg_catalog',
        current_schema(), current_schema());
    EXECUTE format('ALTER FUNCTION %I.validate_plugin_webhook_actor_target_084() SECURITY DEFINER', current_schema());
END;
$migration_541_definer$;
