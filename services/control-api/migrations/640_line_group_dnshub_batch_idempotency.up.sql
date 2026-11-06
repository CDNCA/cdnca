-- 640（前驱 639_probe_dnspup_unified）：
-- migration_id、错误码和 contract 测试）：补三个接口的 Idempotency-Key 同键异体冲突检测。
-- 1. POST /v1/node-line-groups/{id}/platform-default、PUT .../smart-schedule：原来 handler 读了键后丢弃，
--    同键换体照常写入。改为走 node_scheduling_write_requests（与 group.put/delete 同一套 claimWrite），
--    operation CHECK 加 node_scheduling.group.platform_default、node_scheduling.group.smart_schedule（233 的列表 + 2 项）。
-- 2. POST /v1/dns/hub/records/batch：原来只有逐项幂等（第 i 项键 <key>.<i>），同键换体逐项 409、整批仍 200。
--    新表 tenant_dns_record_batch_requests 记批次键对应的请求摘要，同键异体在执行任何一项之前返回 409；
--    同键同体照常逐项执行，已执行的项由 tenant_dns_record_ops 回放。
-- 不改已有数据、不新增权限码。
LOCK TABLE schema_migrations, node_scheduling_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_640_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 639 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 639 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=639 AND
        migration_id='639_probe_dnspup_unified' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.tenant_dns_record_ops') IS NULL OR
          to_regclass(current_schema() || '.tenant_dns_record_batch_requests') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 640 requires the exact verified 639 release head' USING ERRCODE='P6400';
    END IF;
END;
$migration_640_up$;

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_operation_check,
    ADD CONSTRAINT node_scheduling_write_requests_operation_check CHECK (operation IN (
        'node_scheduling.group.put',
        'node_scheduling.group.create',
        'node_scheduling.group.update',
        'node_scheduling.group.rollback',
        'node_scheduling.group.delete',
        'node_scheduling.target_snapshot.create',
        'node_scheduling.group.platform_default',
        'node_scheduling.group.smart_schedule'
    ));

CREATE TABLE tenant_dns_record_batch_requests (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$'),
    -- 规范化后的 items（逐项按 JSON 重编码）的 SHA-256。
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (scope_id, actor_user_id, idempotency_key)
);
