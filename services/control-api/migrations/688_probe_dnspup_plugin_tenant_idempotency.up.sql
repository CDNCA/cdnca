-- 688（前驱 687_active_config_identity_rollback_failed_serving）。
-- 平台持有的插件安装可以授权给多个租户（636）。拨测插件接口改为按 636 的覆盖关系认可这类安装后，
-- 同一个安装会代多个租户发起拨测，幂等键只在「安装 + 租户」内有意义：639 的唯一索引只按
-- (installation_id, idempotency_key)，两个租户碰巧用同一个键时，后到的会被当成重放或撞上唯一约束。
-- 这里把唯一索引换成 (installation_id, tenant_scope_id, idempotency_key)。旧索引更严，已有行都满足新索引，
-- 不改表、不回填。每安装的分钟限速仍按 probe_dnspup_plugin_requests_rate_639_idx(installation_id, created_at)。
-- 错误码：头检查 P6880；down 头检查 P6881；down 遇到跨租户同键 P6882。
LOCK TABLE schema_migrations, probe_dnspup_plugin_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_688_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 687 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 687 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=687 AND
        migration_id='687_active_config_identity_rollback_failed_serving' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('probe_dnspup_plugin_requests_idem_639_uq') IS NULL
         OR to_regclass('probe_dnspup_plugin_requests_idem_688_uq') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 688 requires the exact verified 687 release head' USING ERRCODE='P6880';
    END IF;
END;
$migration_688_up$;

CREATE UNIQUE INDEX probe_dnspup_plugin_requests_idem_688_uq
    ON probe_dnspup_plugin_requests(installation_id, tenant_scope_id, idempotency_key)
    WHERE origin = 'plugin';
DROP INDEX probe_dnspup_plugin_requests_idem_639_uq;
