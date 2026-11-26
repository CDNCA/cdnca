-- 688 回滚：拨测插件请求的幂等唯一索引恢复为 639 的 (installation_id, idempotency_key)。
-- 若同一安装已有两个租户用了同一个幂等键，旧索引建不起来；不删任何请求，直接拒绝回滚（P6882），
-- 等这些请求过期被保留期清理（643）后再回滚。
LOCK TABLE schema_migrations, probe_dnspup_plugin_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_688_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 688 OR
       (SELECT max(version) FROM schema_migrations) <> 688 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=688 AND
        migration_id='688_probe_dnspup_plugin_tenant_idempotency' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 688 down requires the exact verified migration head' USING ERRCODE='P6881';
    END IF;
    IF EXISTS (
        SELECT 1 FROM probe_dnspup_plugin_requests WHERE origin = 'plugin'
        GROUP BY installation_id, idempotency_key HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'migration 688 down: tenants of one installation share an idempotency key' USING ERRCODE='P6882';
    END IF;
END;
$migration_688_down$;

CREATE UNIQUE INDEX probe_dnspup_plugin_requests_idem_639_uq ON probe_dnspup_plugin_requests(installation_id, idempotency_key)
    WHERE origin = 'plugin';
DROP INDEX probe_dnspup_plugin_requests_idem_688_uq;
