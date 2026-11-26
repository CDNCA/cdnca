-- 699（前驱 698_package_subscription_suspend_source）。
-- 计费对接调用日志记请求编号：billing_bridge_logs.request_id 与响应头 X-Request-ID、错误体 request_id 同值
-- （主控入口校验后的请求编号），699 之前的行为 NULL。管理端按 owner 加请求编号/外部服务编号筛选，各配一个部分索引。
-- reason_code：denied 仍必须有原因；通过鉴权的调用失败时可记其错误码（如 bridge_service_not_found），也允许为空
-- （699 之前的失败行）；success 不带原因。
-- 错误码：头检查 P6990；down 头检查 P6991。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_699_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 698 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 698 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=698 AND
        migration_id='698_package_subscription_suspend_source' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='billing_bridge_logs' AND column_name='request_id'
       ) THEN
        RAISE EXCEPTION 'migration 699 requires the exact verified 698 release head' USING ERRCODE='P6990';
    END IF;
END;
$migration_699_up$;

ALTER TABLE billing_bridge_logs
    ADD COLUMN request_id text
        CONSTRAINT billing_bridge_logs_request_id_699_check CHECK (request_id IS NULL OR request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    DROP CONSTRAINT billing_bridge_logs_reason_556_check,
    ADD CONSTRAINT billing_bridge_logs_reason_699_check CHECK (
        (result <> 'denied' OR reason_code IS NOT NULL) AND (result <> 'success' OR reason_code IS NULL));

CREATE INDEX billing_bridge_logs_request_699_idx ON billing_bridge_logs (owner_scope_id, request_id, created_at DESC, id DESC)
    WHERE request_id IS NOT NULL;
CREATE INDEX billing_bridge_logs_service_699_idx
    ON billing_bridge_logs (owner_scope_id, external_service_id, created_at DESC, id DESC)
    WHERE external_service_id IS NOT NULL;
